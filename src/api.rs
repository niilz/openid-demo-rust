use crate::request::Request;
use rocket::http::ContentType;
use std::env;

// withouth ? for start of query, which is added by "to_url"
const OPENID_PROVIDER: &'static str = "https://accounts.google.com/o/oauth2/v2/auth";

#[get("/start")]
pub async fn start_demo() -> (ContentType, String) {
    let client_id = env::var("CLIENT_ID").expect("Please define client ID (get it from google-app-credentials-dashboard) as env-var CLIENT_ID");
    println!("starting the dance");
    let req = Request::new(&client_id);
    let url = req.to_url(OPENID_PROVIDER.to_string());
    println!("The url: {}", url);
    let res = reqwest::get(url)
        .await
        .ok()
        .unwrap()
        .text()
        .await
        .ok()
        .unwrap();
    println!("Got the res: {}...", &res[0..100]);
    (ContentType::HTML, res)
}

#[get("/success?<query..>")]
pub fn handle_success(query: String) {
    println!("Ther Query: {}", query);
}
