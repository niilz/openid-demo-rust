use crate::request::Request;
use rocket::http::ContentType;
use std::env;

const OPENID_PROVIDER: &'static str = "https://accounts.google.com/o/oauth2/v2/auth?";

#[get("/start")]
pub async fn start_demo() -> (ContentType, String) {
    let client_id = env::var("CLIENT_ID").expect("Please define client ID as env-var CLIENT_ID");
    println!("starting the dance");
    let req = Request::new(&client_id);
    let res = reqwest::get(req.to_url(OPENID_PROVIDER.to_string()))
        .await
        .ok()
        .unwrap()
        .text()
        .await
        .ok()
        .unwrap();
    (ContentType::HTML, res)
}

#[get("/success?<query..>")]
pub fn handle_success(query: String) {
    println!("Ther Query: {}", query);
}
