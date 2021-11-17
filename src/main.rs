#[macro_use]
extern crate rocket;

use openid::api::*;
use openid::credentials::Credentials;
use openid::service::user::InMemoryUserRepository;
use std::sync::Mutex;

#[launch]
fn app() -> _ {
    let credentials = Credentials::init();

    rocket::build()
        .manage(Mutex::new(InMemoryUserRepository::default()))
        .manage(CurrentState::default())
        .manage(credentials)
        .mount("/", routes![login, handle_success])
}
