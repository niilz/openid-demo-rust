use crate::request::Request;
use rocket::{response::Redirect, State};
use std::env;
use std::sync::Mutex;

// without ? for start of query, which is added by "to_url"
const OPENID_PROVIDER: &'static str = "https://accounts.google.com/o/oauth2/v2/auth";

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

#[get("/start")]
pub async fn start_demo(request_state: &State<CurrentState>) -> Redirect {
    let client_id = env::var("CLIENT_ID").expect("Please define client ID (get it from google-app-credentials-dashboard) as env-var CLIENT_ID");
    let req = Request::new(&client_id);
    let state = req.get_state().to_string();
    request_state.init_for_req(state);
    let url = req.to_url(OPENID_PROVIDER.to_string());
    Redirect::to(url)
}

#[get("/success?<query..>")]
pub fn handle_success(query: String, local_state: &State<CurrentState>) {
    println!("Ther Query: {}", query);
    println!(
        "And this is the local state: {:?}. Are they the same?",
        local_state.inner().0.lock().unwrap()
    );
}
