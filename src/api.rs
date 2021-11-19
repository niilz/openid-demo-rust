use crate::{
    credentials::Credentials,
    jwt::{destruct_jwt, Payload},
    request::{AuthCodeRequest, TokenRequest},
    response::TokenResponse,
    service::user::{Conserved, InMemoryUserRepository, User},
};
use rocket::{
    response::Redirect,
    serde::json::{self as sjson, json, Value},
    State,
};
use std::fmt::Debug;
use std::sync::Mutex;

const AUTH_CODE_URL: &'static str = "https://accounts.google.com/o/oauth2/v2/auth?";
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

#[derive(Default, Debug)]
pub struct CurrentState(Mutex<String>);
impl CurrentState {
    pub fn init_for_req(&self, new_state: String) {
        if let Ok(mut state) = self.0.lock() {
            *state = new_state;
        } else {
            eprint!("Could not set new sate for code-flow-start-request");
        }
    }
}

impl CurrentState {
    fn cmp_inner_with(&self, other: impl AsRef<str>) -> bool {
        match self.0.lock() {
            Ok(token) => *token == other.as_ref(),
            Err(e) => panic!("Could not get the lock to the inner. Err: {}", e),
        }
    }
}

#[get("/login")]
pub async fn login(
    request_state: &State<CurrentState>,
    credentials: &State<Credentials>,
) -> Redirect {
    // Step: 1 (Authentication-Request)

    // Collect the values that make up an OIDC-Auth-Code-Request
    let req = AuthCodeRequest::new(&credentials.client_id);
    // Store the state to be able to compare it later (prevent replay-attacks)
    let state = req.get_state().to_string();
    request_state.init_for_req(state);
    // Turn all values into OIDC-compliant Request-Query
    let url = req.to_url(AUTH_CODE_URL.to_string());
    // Redircet to the cunstructed request-url
    // (Also see: 3.1.2 Authorization Endpoint at
    // https://openid.net/specs/openid-connect-core-1_0.html)
    //
    // After a sucessful User-Login, the IP redirect to
    // the specified 'redirect_uri'
    Redirect::to(url)
}

// Handle the authorization-code-response
// This edpoint is called by the IP, if the User-Login was
// sucessful
//
// The query contains the state-nounce we send in the Authentication-
// Rquest, AND the Authorization-Code.
// Other query-params like email are ignored
#[get("/success?<state>&<code>")]
pub async fn handle_success(
    state: &str,
    code: &str,
    local_state: &State<CurrentState>,
    credentials: &State<Credentials>,
    user_repo: &State<Mutex<InMemoryUserRepository>>,
) -> Value {
    // Step: 2 (Token Request)

    // First: Check that state-nounce is the once we sent in step 1
    if !local_state.cmp_inner_with(state) {
        return json!({"Error": "Cross-Site-Request-Forgery is not cool!"});
    }
    // Second: Ask for access- and id-token, by providing the authorization-
    // code we retreived in in the quer-parameters (perfomed as a POST-request)
    let (_access_token, id_token) =
        get_tokens(code, &credentials.client_id, &credentials.client_secret).await;

    // Step: 3 (Obtain user-data/claims)
    // Decode the identity-token to obtain user-information
    let jwt = destruct_jwt(&id_token).unwrap();
    let payload: Payload = sjson::from_str(&jwt.payload).unwrap();
    //  Optional TODO: validate token-authenticity with signature

    // Step: 4
    // Save the User to the database, if not exist

    // TODO:
    // Create a session
    //let session: Option<Session> = session_service.start_session(user_data);
    json!("TODO")
}

async fn get_tokens(code: &str, client_id: &str, client_secret: &str) -> (String, String) {
    let token_request = TokenRequest::new(code, client_id, client_secret);

    // Get the access- and the identity-token
    let res = reqwest::Client::new()
        .post(TOKEN_ENDPOINT)
        .form(&token_request)
        .send()
        .await
        .unwrap();

    let token_response = res.json::<TokenResponse>().await.unwrap();
    (token_response.access_token, token_response.id_token)
}

fn session_user(
    user_repo: &mut Mutex<InMemoryUserRepository>,
    user_name: String,
) -> User<Conserved> {
    // If new, save User to Repo
    let mut repo = user_repo.lock().unwrap();
    if let Some(user) = repo.get_user_by_name(&user_name) {
        user
    } else {
        let new_user = User::new(user_name);
        let id = repo.save(new_user);
        repo.get_user_by_id(id).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::api::session_user;
    use crate::service::user::InMemoryUserRepository;

    use super::CurrentState;
    use std::sync::Mutex;

    #[test]
    fn can_turn_state_into_string() {
        let expected = "inner_token".to_string();
        let state = CurrentState(Mutex::new("inner_token".to_string()));
        assert!(state.cmp_inner_with(expected));
    }

    #[test]
    fn create_user_if_not_present() {
        let repo = InMemoryUserRepository::default();
        assert_eq!(repo.get_idx(), 0);
        let mut repo = Mutex::new(repo);

        // Non existing user creates a new user and stores it
        let user = session_user(&mut repo, "Marty".to_string());
        assert_eq!(repo.lock().unwrap().get_idx(), 1);
        assert_eq!(user.get_name(), "Marty");
    }

    #[test]
    fn existing_user_does_not_increase_the_idx() {
        let repo = InMemoryUserRepository::default();
        assert_eq!(repo.get_idx(), 0);

        let mut repo = Mutex::new(repo);

        // Persiste a new user and check it's id
        let new_user = session_user(&mut repo, "Marty".to_string());
        // Index has increased by one
        let repo_lock = repo.lock().unwrap();
        assert_eq!(repo_lock.get_idx(), 1);
        drop(repo_lock);

        let repo_lock = repo.lock().unwrap();
        let persited_user = repo_lock.get_user_by_id(1);
        drop(repo_lock);
        assert_eq!(Ok(new_user), persited_user);

        // Getting an already existing user
        let unchanged_user = session_user(&mut repo, persited_user.unwrap().get_name().to_string());

        // Id is not increased
        assert_eq!(repo.lock().unwrap().get_idx(), 1);
        // Id and name of the user are still the same
        assert_eq!(unchanged_user.get_id(), 1);
        assert_eq!(unchanged_user.get_name(), "Marty");
    }
}
