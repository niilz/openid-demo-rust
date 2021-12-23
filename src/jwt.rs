#![allow(unused_variables)]
use ring::signature;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[allow(dead_code)]
const ALLOWED_ISSUERS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Jwt {
    pub header: Header,
    pub payload: Payload,
    pub signature: Option<String>,
}

#[allow(dead_code)]
impl Jwt {
    // Validation of the authenticity of the ID-Token
    fn validate(&self, public_key: Vec<u8>) -> bool {
        // 1. Verify that the ID token is properly signed by the issuer. Google-issued tokens are
        //    signed using one of the certificates found at the URI specified in the jwks_uri
        //    metadata value of the Discovery document.
        let signature_bytes =
            base64::decode(self.signature.as_ref().unwrap()).expect("Could not decode signature");

        // Get base64(header).base64(paload)
        let header_and_payload_base64 = self
            .header_and_payload_base64()
            .expect("Could not transform header and payload to base64");

        // Create Public-Key struct from key-bytes
        let public_key =
            signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, public_key);

        // Check that the signature matches the base64_enoced header.payload
        match public_key.verify(&header_and_payload_base64.as_bytes(), &signature_bytes) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("The signature does not match the token");
                false
            }
        }
    }

    fn header_and_payload_base64(&self) -> serde_json::Result<String> {
        let config = base64::Config::new(base64::CharacterSet::UrlSafe, false);
        let head_base64 = base64::encode_config(serde_json::to_string(&self.header)?, config);
        let payload_base64 = base64::encode_config(serde_json::to_string(&self.payload)?, config);
        Ok(format!("{}.{}", head_base64, payload_base64))
    }
}

pub fn destruct_jwt(id_token: impl AsRef<str>) -> Result<Jwt, &'static str> {
    let parts = get_token_parts(id_token.as_ref());
    if let [header, payload] = &parts[..] {
        return Ok(Jwt {
            header: serde_json::from_str(header).unwrap(),
            payload: serde_json::from_str(payload).unwrap(),
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

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Default, Clone)]
pub struct Header {
    alg: String, // "RS256"
    kid: String, // "c1892eb49d7ef9adf8b2e14c05ca0d032714a237",
    typ: String, // "JWT"
}

// Only implements default, to make it easier to test
#[derive(Deserialize, Serialize, Debug, Default, PartialEq, Eq, Clone)]
pub struct Payload {
    // ALWAYS: The audience that this ID token is intended for
    pub aud: String,
    // ALWAYS: Expiration time on or after which the ID token must not be accepted. Represented in Unix time (integer seconds).
    pub exp: i64,
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

#[allow(dead_code)]
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
        if self.aud != client_id {
            return false;
        }
        // 4. Verify that the expiry time (exp claim) of the ID token has not passed.
        if self.exp <= OffsetDateTime::now_utc().unix_timestamp() {
            return false;
        }
        true
    }
}

#[derive(Deserialize, PartialEq, Eq, Debug)]
struct Jwks {
    keys: Vec<Key>,
}

#[derive(Deserialize, PartialEq, Eq, Debug)]
struct Key {
    kty: String, // "RSA"
    #[serde(rename = "use")]
    usage: String, // "sig"
    e: String,   // "AQAB"
    kid: String, // "032b2ef3d2c2806157f8a9b9f4ef779834f85ada"
    n: String,   // "1Zdt2akTl0LcFko5ksUyL1caOq0zHO0ijzfKV8Z9vAGA1...."
    alg: String, // "RS256
}

#[cfg(test)]
mod tests {

    use crate::jwt::Header;
    use crate::jwt::Jwks;
    use crate::jwt::Key;
    use crate::jwt::{destruct_jwt, get_token_parts, Jwt, Payload};
    use ring::signature;
    use std::{ops::Add, time::Duration};
    use time::OffsetDateTime;

    fn get_test_header() -> Header {
        Header {
            alg: "RS256".to_string(),
            kid: "some-code-123".to_string(),
            typ: "JWT".to_string(),
        }
    }

    fn get_test_payload() -> Payload {
        // minimal Payload
        let mut payload = Payload::default();
        payload.iss = "the-iss".to_string();
        payload.aud = "the-client-id".to_string();
        payload
    }

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
    fn can_destructure_jwt() -> serde_json::Result<()> {
        let header = get_test_header();
        let payload = get_test_payload();
        let signature = "ignored".to_string();

        let id_token = [
            serde_json::to_string(&header)?,
            serde_json::to_string(&payload)?,
            signature,
        ]
        .iter()
        .map(|part| base64::encode(part))
        .collect::<Vec<String>>()
        .join(".");

        let expected_jwt = Jwt {
            header,
            payload,
            signature: None,
        };

        let jwt = destruct_jwt(id_token).unwrap();
        assert_eq!(expected_jwt, jwt);
        Ok(())
    }

    #[test]
    fn can_validate_payload_of_id_token() {
        let mut dummy_id_token = Payload::default();
        dummy_id_token.iss = "accounts.google.com".to_string();
        dummy_id_token.aud = "123456.apps.googleusercontent.com".to_string();
        dummy_id_token.exp = OffsetDateTime::now_utc()
            .add(Duration::from_secs(1))
            .unix_timestamp();
        let is_valid = dummy_id_token.validate("123456.apps.googleusercontent.com");
        assert!(is_valid);
    }

    #[test]
    fn fails_if_aud_and_client_are_not_the_same() {
        let mut dummy_id_token = Payload::default();
        dummy_id_token.iss = "accounts.google.com".to_string();
        dummy_id_token.aud = "123456.apps.googleusercontent.com".to_string();
        dummy_id_token.exp = OffsetDateTime::now_utc()
            .add(Duration::from_secs(1))
            .unix_timestamp();
        let is_valid = dummy_id_token.validate("different-id-than-aud.com");
        assert!(!is_valid);
    }

    #[test]
    fn fails_if_token_has_expired() {
        let mut dummy_id_token = Payload::default();
        dummy_id_token.iss = "accounts.google.com".to_string();
        dummy_id_token.aud = "123456.apps.googleusercontent.com".to_string();
        // This moment will have passed when the assertion happens
        dummy_id_token.exp = OffsetDateTime::now_utc().unix_timestamp();
        let is_valid = dummy_id_token.validate("123456.apps.googleusercontent.com");
        assert!(!is_valid);
    }

    #[test]
    fn can_deserialize_jwks() {
        let serialized_key = r#"{
            "kty": "RSA",
            "use": "sig",
            "e": "AQAB",
            "kid": "032b2ef3d2c2806157f8a9b9f4ef779834f85ada",
            "n": "1Zdt2akTl0LcFko5ksUyL1caOq0zHO0ijzfKV",
            "alg": "RS256"
        }"#;

        let expected_key = Key {
            kty: "RSA".to_string(),
            usage: "sig".to_string(),
            e: "AQAB".to_string(),
            kid: "032b2ef3d2c2806157f8a9b9f4ef779834f85ada".to_string(),
            n: "1Zdt2akTl0LcFko5ksUyL1caOq0zHO0ijzfKV".to_string(),
            alg: "RS256".to_string(),
        };

        let deserialized_key: Key = serde_json::from_str(serialized_key).unwrap();
        assert_eq!(expected_key, deserialized_key);

        let serialized_jwks = format!(
            r#"{{
            "keys": [
                {}
            ]
        }}"#,
            serialized_key
        );

        let deserialized_jwks = serde_json::from_str(&serialized_jwks).unwrap();

        let expected_jwks = Jwks {
            keys: vec![expected_key],
        };
        assert_eq!(expected_jwks, deserialized_jwks);
    }

    // Impl just for tests
    impl Jwt {
        fn sign_jwt(&mut self, private_key: Vec<u8>) -> serde_json::Result<()> {
            let alg = self.header.alg.clone();
            let jwt_base64 = self.header_and_payload_base64()?;

            // Construct ring-KeyPair
            let rsa_key_pair =
                RsaKeyPair::from_der(&private_key).expect("Could not create key-pair");
            let rand = rand::SystemRandom::new();
            let mut signature = vec![0; rsa_key_pair.public_modulus_len()];
            // Sign the JWT (into the signature buffer ^)
            rsa_key_pair
                .sign(
                    &signature::RSA_PKCS1_SHA256,
                    &rand,
                    jwt_base64.as_bytes(),
                    &mut signature,
                )
                .expect("Could not sign the JWT");

            let signature_base_64 = base64::encode(signature);
            self.signature = Some(signature_base_64);

            Ok(())
        }
    }

    use ring::{rand, signature::RsaKeyPair};
    use std::fs;

    #[test]
    fn can_validate_the_id_token_signature() {
        // Construct dummy-JWT
        let header = get_test_header();
        let payload = get_test_payload();
        let mut jwt = Jwt {
            header,
            payload,
            signature: None,
        };
        // Load private-test-key (created with openssl) from filesystem
        let private_key = fs::read("test-private-key.der").expect("Could not read the keyfile");

        // Sign the dummy-JWT with test-private-key
        let jwt_with_signature = jwt
            .sign_jwt(private_key)
            .expect("Could not sign the Dummy-JWT");

        // Read test-public-key from filesystem
        let public_key = fs::read("test-public-key.der").expect("Could not read public key");

        // validate the JWT
        let is_valid = jwt.validate(public_key);

        assert!(is_valid);
    }
}
