use rand::{thread_rng, Rng};
use serde::Serialize;
use to_url::ToUrl;

const REDIRECT_URI: &str = "http://localhost:8000/success";

#[derive(Debug, ToUrl)]
pub struct AuthCodeRequest<'a> {
    response_type: &'a str,
    client_id: &'a str,
    scope: Vec<&'a str>,
    redirect_uri: &'a str,
    state: String, // security_token%3D138r5719ru3e1%26url%3Dhttps%3A%2F%2Foauth2-login-demo.example.com%2FmyHome&
    login_hint: &'a str, // jsmith@example.com
    nonce: String,
}

impl<'a> AuthCodeRequest<'a> {
    pub fn new(client_id: &'a str) -> Self {
        AuthCodeRequest {
            response_type: "code",
            client_id, // e.g 424911365001.apps.googleusercontent.com&
            scope: vec!["openid", "email", "profile"],
            redirect_uri: REDIRECT_URI,
            state: generate_sec_token(42),
            login_hint: "daredevdiary@gmail.com",
            nonce: generate_nonce(),
        }
    }

    pub fn get_state(&self) -> &str {
        &self.state
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
        "security-token-1234567890SauerkrautSafthttpsKeepItSafe-{}",
        special_number
    )
}

// TODO: Probably don't need ToUrl anymore
#[derive(Debug, ToUrl, Serialize)]
pub struct TokenRequest<'a> {
    code: &'a str,
    client_id: &'a str,
    client_secret: &'a str,
    redirect_uri: &'a str,
    grant_type: &'a str, // authorization_code
}

impl<'a> TokenRequest<'a> {
    pub fn new(code: &'a str, client_id: &'a str, client_secret: &'a str) -> Self {
        TokenRequest {
            code,
            client_id,
            client_secret,
            redirect_uri: REDIRECT_URI,
            grant_type: "authorization_code",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_url_creates_correct_url_for_auth_request() {
        let dummy_req = AuthCodeRequest {
            response_type: "code",
            client_id: "1234andSomeText", // e.g 424911365001.apps.googleusercontent.com&
            scope: vec!["openid", "email", "profile"],
            redirect_uri: "http://dummy-redirect.com",
            state: "security_token0815".to_string(), // generate_sec_token(42),
            login_hint: "dummy@gmail.com",
            nonce: "80085-3531".to_string(), // generate_nonce(),
        };
        assert_eq!(
            dummy_req.to_url("https://my-dummy-op?".to_string()),
            "https://my-dummy-op?\
                response_type=code&\
                client_id=1234andSomeText&\
                scope=openid%20email%20profile&\
                redirect_uri=http://dummy-redirect.com&\
                state=security_token0815&\
                login_hint=dummy@gmail.com&\
                nonce=80085-3531"
                .to_string()
        );
    }

    #[test]
    fn to_url_creates_correct_url_for_token_request() {
        let dummy_req = TokenRequest {
            code: "you-gave-me-this-123",
            client_id: "1234andSomeText", // e.g 424911365001.apps.googleusercontent.com&
            client_secret: "psssecret",
            redirect_uri: "http://dummy-redirect.com",
            grant_type: "authorization_code",
        };
        assert_eq!(
            dummy_req.to_url("".to_string()),
            "code=you-gave-me-this-123&\
            client_id=1234andSomeText&\
            client_secret=psssecret&\
            redirect_uri=http://dummy-redirect.com&\
            grant_type=authorization_code"
                .to_string()
        );
    }
}
