#[macro_use]
extern crate rocket;

use openid::api::*;

//#[tokio::main]
#[launch]
fn app() -> _ {
    //let res = reqwest::get("http://google.de").await?.text().await?;
    //println!("{:?}", res);

    rocket::build()
        .manage(CurrentState::default())
        .mount("/", routes![start_demo, handle_success])
}
