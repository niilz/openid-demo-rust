use serde::Deserialize;

const ALLOWED_ISSUERS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];

#[derive(Debug, PartialEq, Eq)]
pub struct Jwt {
    pub header: String,
    pub payload: String,
    pub signature: Option<String>,
}

impl Jwt {
    // Validation of the authenticity of the ID-Token
    fn validate(&self) -> bool {
        // 1. Verify that the ID token is properly signed by the issuer. Google-issued tokens are
        //    signed using one of the certificates found at the URI specified in the jwks_uri
        //    metadata value of the Discovery document.
        todo!("Implement signature validation")
    }
}

pub fn destruct_jwt(id_token: impl AsRef<str>) -> Result<Jwt, &'static str> {
    let parts = get_token_parts(id_token.as_ref());
    if let [header, payload] = &parts[..] {
        return Ok(Jwt {
            header: header.to_string(),
            payload: payload.to_string(),
            // TODO: Decrypt-Signature
            signature: None,
        });
    };
    Err("Token has unsupported format")
}

fn get_token_parts(id_token: &str) -> Vec<String> {
    let token_parts = id_token.split('.');
    let header_and_payload = token_parts
        .take(2)
        .filter_map(|part| base64::decode(part).ok())
        .filter_map(|part| String::from_utf8(part).ok())
        .collect();
    header_and_payload
}

// Only implements default, to make it easier to test
#[derive(Deserialize, Debug, Default)]
pub struct Payload {
    // ALWAYS: The audience that this ID token is intended for
    pub aud: String,
    // ALWAYS: Expiration time on or after which the ID token must not be accepted. Represented in Unix time (integer seconds).
    pub exp: u32,
    // ALWAYS: The time the ID token was issued. Represented in Unix time (integer seconds).
    pub iat: u32,
    // ALWAYS: The Issuer Identifier for the Issuer of the response. Always https://accounts.google.com or accounts.google.com for Google ID tokens
    pub iss: String,
    // ALWAYS: An identifier for the user, unique among all Google accounts and never reused
    pub sub: String,

    // The client_id of the authorized presenter
    pub azp: String,
    // "user@email.com",
    pub email: String,
    // True if the user's e-mail address has been verified; otherwise false.
    pub email_verified: bool,
    // Access token hash. Provides validation that the access token is tied to the identity token.
    pub at_hash: String,
    // The value of the nonce supplied by your app in the authentication request
    pub nonce: String,
    // The Users full name
    pub name: String,
    // The URL of the user's profile picture
    pub picture: String,
    // The user's given name(s) or first name(s).
    pub given_name: String,
    // The user's surname(s) or last name(s).
    pub family_name: String,
    // The user's locale, represented by a BCP 47 language tag
    pub locale: String,
}

impl Payload {
    fn validate(&self, client_id: &str) -> bool {
        // 2. Verify the value of the iss claim in the ID token
        if !ALLOWED_ISSUERS.contains(&self.iss.as_ref()) {
            return false;
        }
        if self.aud != client_id {
            return false;
        }
        // 3. Verify that the value of the aud claim in the ID token is equal to your app's client ID.
        // 4. Verify that the expiry time (exp claim) of the ID token has not passed.
        // 5. If you specified a hd parameter value in the request, verify that the ID token has a
        //    hd claim that matches an accepted G Suite hosted domain.
        todo!("Verification Steps")
    }
}

#[cfg(test)]
mod tests {
    use crate::jwt::{destruct_jwt, get_token_parts, Jwt, Payload};

    #[test]
    fn can_get_token_parts() {
        let header = "header-stuff-algo-256";
        let payload = "payload-12345-claims";

        let header_en = base64::encode(header);
        let payload_en = base64::encode(payload);

        let id_token = format!("{}.{}", header_en, payload_en);

        let expected_parts = vec!["header-stuff-algo-256", "payload-12345-claims"];
        let parts = get_token_parts(&id_token);
        assert_eq!(expected_parts, parts);
    }

    #[test]
    fn can_destructure_jwt() {
        let header = "header-stuff-algo-256";
        let payload = "payload-12345-claims";
        let signature = "ignored";

        let id_token = [header, payload, signature]
            .iter()
            .map(|part| base64::encode(part))
            .collect::<Vec<String>>()
            .join(".");

        let expected_jwt = Jwt {
            header: "header-stuff-algo-256".to_string(),
            payload: "payload-12345-claims".to_string(),
            signature: None,
        };

        let jwt = destruct_jwt(id_token).unwrap();
        assert_eq!(expected_jwt, jwt);
    }

    #[test]
    fn can_validate_the_id_token_signature() {
        let id_token = Jwt {
            header: "algo-and-stuff".to_string(),
            payload: "iss-and-stuff".to_string(),
            signature: Some("123xyz".to_string()),
        };
        assert!(id_token.validate());
    }

    #[test]
    fn can_validate_payload_of_id_token() {
        let mut dummy_id_token = Payload::default();
        dummy_id_token.aud = "123456.apps.googleusercontent.com".to_string();
        dummy_id_token.iss = "accounts.google.com".to_string();
        dummy_id_token.validate("very-secret-client-id");
    }
}
