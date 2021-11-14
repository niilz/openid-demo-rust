use crate::{
    credentials::Credentials,
    jwt::{destruct_jwt, Payload},
    request::{AuthCodeRequest, TokenRequest},
    response::TokenResponse,
};
use rocket::{
    response::Redirect,
    serde::json::{self, json, Value},
    State,
};
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
    // Step: 1 (Authorization-Request)

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
    Redirect::to(url)
}

// Handle the authorization-code-response
#[get("/success?<state>&<code>")]
pub async fn handle_success(
    state: &str,
    code: &str,
    local_state: &State<CurrentState>,
    credentials: &State<Credentials>,
) -> Value {
    if !local_state.cmp_inner_with(state) {
        return json!("Cross-Site-Request-Forgery is not cool!");
    }
    let (_access_token, id_token) =
        get_tokens(code, &credentials.client_id, &credentials.client_secret).await;

    let jwt = destruct_jwt(&id_token).unwrap();
    let payload: Payload = json::from_str(&jwt.payload).unwrap();

    // TODO: Use ID-Token:
    //  - optional: validate (use Signature to verify token-authenticity)
    //  - read claims
    json!(format!("header: {},\npayload: {:?}", jwt.header, payload))
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

#[cfg(test)]
mod tests {
    use super::CurrentState;
    use std::sync::Mutex;

    #[test]
    fn can_turn_state_into_string() {
        let expected = "inner_token".to_string();
        let state = CurrentState(Mutex::new("inner_token".to_string()));
        assert!(state.cmp_inner_with(expected));
    }
}
