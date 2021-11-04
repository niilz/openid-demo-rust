use crate::request::{AuthCodeRequest, TokenRequest};
use rocket::{
    response::Redirect,
    serde::json::{json, Value},
    State,
};
use std::env;
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

#[get("/start")]
pub async fn start_demo(request_state: &State<CurrentState>) -> Redirect {
    let client_id = env::var("CLIENT_ID").expect("Please define client ID (get it from google-app-credentials-dashboard) as env-var CLIENT_ID");
    let req = AuthCodeRequest::new(&client_id);
    let state = req.get_state().to_string();
    request_state.init_for_req(state);
    let url = req.to_url(AUTH_CODE_URL.to_string());
    Redirect::to(url)
}

#[get("/success?<state>&<code>")]
pub async fn handle_success(state: &str, code: &str, local_state: &State<CurrentState>) -> Value {
    let client_id = env::var("CLIENT_ID").expect("Please define client ID (get it from google-app-credentials-dashboard) as env-var CLIENT_ID");
    let client_secret = env::var("CLIENT_SECRET").expect("Please define client secret (get it from google-app-credentials-dashboard) as env-var CLIENT_SECRET");
    println!("Ther state: {}", state);
    println!("Ther code: {}", code);
    if !local_state.cmp_inner_with(state) {
        return json!("Cross-Site-Request-Forgery is not cool!");
    }
    let (access_token, id_token) = get_tokens(code, &client_id, &client_secret).await;
    json!("Getting the ID-Token")
}

async fn get_tokens(code: &str, client_id: &str, client_secret: &str) -> (String, String) {
    let token_request = TokenRequest::new(code, client_id, client_secret);
    let res = reqwest::Client::new()
        .post(TOKEN_ENDPOINT)
        .form(&token_request.to_url("".to_string()))
        .send()
        .await
        .unwrap();
    ("auth".to_string(), "id".to_string())
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
