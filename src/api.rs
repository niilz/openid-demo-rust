use crate::request::Request;
use rocket::{response::Redirect, State};
use std::env;
use std::sync::Mutex;

// withouth ? for start of query, which is added by "to_url"
const OPENID_PROVIDER: &'static str = "https://accounts.google.com/o/oauth2/v2/auth";

#[derive(Default, Debug)]
pub struct CurrentState(pub Mutex<String>);
impl CurrentState {
    fn set_state(&self, new_state: String) {
        if let Ok(mut state) = self.0.lock() {
            *state = new_state;
        }
    }
}

#[get("/start")]
pub async fn start_demo(current_state: &State<CurrentState>) -> Redirect {
    let client_id = env::var("CLIENT_ID").expect("Please define client ID (get it from google-app-credentials-dashboard) as env-var CLIENT_ID");
    let req = Request::new(&client_id);
    let state = req.get_state().to_string();
    current_state.set_state(state);
    let url = req.to_url(OPENID_PROVIDER.to_string());
    Redirect::to(url)
}

#[get("/success?<query..>")]
pub fn handle_success(query: String, local_state: &State<CurrentState>) {
    println!("Ther Query: {}", query);
    println!(
        "And this is the local state: {:?}. Are they the same?",
        local_state
    );
}
