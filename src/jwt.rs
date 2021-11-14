#[derive(Debug, PartialEq, Eq)]
pub struct Jwt {
    pub header: String,
    pub payload: String,
    pub signature: Option<String>,
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

struct Payload {
    // ALWAYS: The audience that this ID token is intended for
    aud: String,
    // ALWAYS: Expiration time on or after which the ID token must not be accepted. Represented in Unix time (integer seconds).
    exp: u32,
    // ALWAYS: The time the ID token was issued. Represented in Unix time (integer seconds).
    iat: u32,
    // ALWAYS: The Issuer Identifier for the Issuer of the response. Always https://accounts.google.com or accounts.google.com for Google ID tokens
    iss: String,
    // ALWAYS: An identifier for the user, unique among all Google accounts and never reused
    sub: String,

    // The client_id of the authorized presenter
    azp: String,
    // "user@email.com",
    email: String,
    // True if the user's e-mail address has been verified; otherwise false.
    email_verified: bool,
    // Access token hash. Provides validation that the access token is tied to the identity token.
    at_hash: String,
    // The value of the nonce supplied by your app in the authentication request
    nonce: String,
    // The Users full name
    name: String,
    // The URL of the user's profile picture
    picture: String,
    // The user's given name(s) or first name(s).
    given_name: String,
    // The user's surname(s) or last name(s).
    family_name: String,
    // The user's locale, represented by a BCP 47 language tag
    locale: String,
}

#[cfg(test)]
mod tests {
    use crate::jwt::{destruct_jwt, get_token_parts, Jwt};

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
}
