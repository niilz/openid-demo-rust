use crate::request::Request;
use rocket::{form::Form, http::ContentType, response::Redirect, uri};
use std::env;

// withouth ? for start of query, which is added by "to_url"
const OPENID_PROVIDER: &'static str = "https://accounts.google.com/o/oauth2/v2/auth";

#[get("/start")]
pub async fn start_demo() -> Redirect {
    let client_id = env::var("CLIENT_ID").expect("Please define client ID (get it from google-app-credentials-dashboard) as env-var CLIENT_ID");
    let req = Request::new(&client_id);
    let url = req.to_url(OPENID_PROVIDER.to_string());
    Redirect::to(url)
}

#[get("/success?<query..>")]
pub fn handle_success(query: String) {
    println!("Ther Query: {}", query);
}
