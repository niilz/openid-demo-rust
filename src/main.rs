#[macro_use]
extern crate rocket;

use openid::api::*;
use openid::credentials::Credentials;

#[launch]
fn app() -> _ {
    let credentials = Credentials::init();

    rocket::build()
        .manage(CurrentState::default())
        .manage(credentials)
        .mount("/", routes![start_demo, handle_success])
}
