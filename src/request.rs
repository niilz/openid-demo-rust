use rand::{thread_rng, Rng};
use to_url::ToUrl;

const REDIRECT_URI: &'static str = "http://localhost:3000/success";

#[derive(Debug, ToUrl)]
pub struct Request<'a> {
    response_type: &'a str,
    client_id: &'a str,
    scope: Vec<&'a str>,
    redirect_uri: &'a str,
    state: String, // security_token%3D138r5719ru3e1%26url%3Dhttps%3A%2F%2Foauth2-login-demo.example.com%2FmyHome&
    // login_hint: String, jsmith@example.com&
    nonce: String,
}

impl<'a> Request<'a> {
    pub fn new(client_id: &'a str) -> Self {
        Request {
            response_type: "code",
            client_id, // e.g 424911365001.apps.googleusercontent.com&
            scope: vec!["openid", "email", "profile"],
            redirect_uri: REDIRECT_URI,
            state: generate_sec_token(42),
            // login_hint: daredevdiary@gmail.com,
            nonce: generate_nonce(),
        }
    }

    pub fn to_query(&self) -> String {
        vec![
            self.response_type,
            self.client_id,
            self.scope.join("%20").as_str(),
            self.redirect_uri,
            &self.state,
            &self.nonce,
        ]
        .iter()
        .map(|part| part.to_string())
        .collect::<Vec<_>>()
        .join("&")
    }
}

pub fn generate_nonce<'a>() -> String {
    // negligently creating a nonce
    let mut rng = thread_rng();
    (0..3)
        .map(|_| (0..7).map(|_| rng.gen_range(0..9).to_string()).collect())
        .collect::<Vec<String>>()
        .join("-")
}

pub fn generate_sec_token<'a>(special_number: u8) -> String {
    // Totally unsecure, hard coded string
    format!(
        "security_token_1234567890SauerkrautSafthttpsKeepItSafe_{}",
        special_number
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_use_macro() {
        let dummy_req = Request {
            response_type: "code",
            client_id: "1234andSomeText", // e.g 424911365001.apps.googleusercontent.com&
            scope: vec!["openid", "email", "profile"],
            redirect_uri: "http://dummy-redirect.com",
            state: "security_token0815".to_string(), // generate_sec_token(42),
            // login_hint: daredevdiary@gmail.com,
            nonce: "80085-3531".to_string(), // generate_nonce(),
        };
        assert_eq!(
            dummy_req.to_url("https://my-dummy-op".to_string()),
            r#"https://my-dummy-op?
response_type=code&
client_id=1234andSomeText&
scope=openid%20email%20%profile&
redirect_uir=http://dummy-redirect.com&
state=security_token0815&
nonce=80085-3531"#
                .to_string()
        );
    }
}
