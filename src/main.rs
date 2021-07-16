#[macro_use]
extern crate rocket;

use openid::api::*;
use openid::request::Request;

//#[tokio::main]
#[launch]
fn app() -> _ {
    //let res = reqwest::get("http://google.de").await?.text().await?;
    //println!("{:?}", res);

    rocket::build().mount("/", routes![start_demo, handle_success])
}
