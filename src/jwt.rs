#![allow(unused_variables)]
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[allow(dead_code)]
const ALLOWED_ISSUERS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Jwt {
    pub header: String,
    pub payload: String,
    pub signature: String,
}

impl Jwt {
    // NOTE: It is maybe not smart to first construct the JWT into an struct
    //      just tho then reparse all its pieces into base64 encoded elements again...

    // Validation of the authenticity of the ID-Token
    pub fn verify_with_public_key(&self, public_key: PKey<Public>) -> bool {
        // 1. Verify that the ID token is properly signed by the issuer. Google-issued tokens are
        //    signed using one of the certificates found at the URI specified in the jwks_uri
        //    metadata value of the Discovery document.

        // Check that the signature matches the base64_enoced header.payload
        let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key).unwrap();
        //let mut verifier = Verifier::new_without_digest(&public_key).unwrap();
        let header_payload = format!("{}.{}", self.header, self.payload);
        match verifier.update(header_payload.as_bytes()) {
            Ok(()) => println!("openssl update worked."),
            Err(e) => eprintln!("openssl update failed. Err: {e}"),
        }
        let signature_bytes = base64::decode_config(&self.signature, base64::URL_SAFE).unwrap();
        //match verifier.verify(&self.signature.as_bytes()) {
        match verifier.verify(&signature_bytes) {
            Ok(has_worked) => {
                println!("openssl varification result: {has_worked}");
                has_worked
            }
            Err(e) => {
                eprintln!("openssl verify failed. Err: {e}");
                false
            }
        }
    }
}

pub fn destruct(id_token: impl AsRef<str>) -> Result<Jwt, &'static str> {
    // println!("the ID_TOKEN: {}", id_token.as_ref());
    let parts: Vec<&str> = id_token.as_ref().split('.').collect();
    if let [header, payload, signature] = &parts[..] {
        return Ok(Jwt {
            header: header.to_string(),
            payload: payload.to_string(),
            signature: signature.to_string(),
        });
    };
    Err("Token has unsupported format")
}

// Only implements default, to make it easier to test
#[derive(Deserialize, Serialize, Debug, Default, PartialEq, Eq, Clone)]
pub struct Payload {
    // ALWAYS: The Issuer Identifier for the Issuer of the response. Always https://accounts.google.com or accounts.google.com for Google ID tokens
    pub iss: String,
    // The client_id of the authorized presenter
    pub azp: String,
    // ALWAYS: The audience that this ID token is intended for
    pub aud: String,
    // ALWAYS: An identifier for the user, unique among all Google accounts and never reused
    pub sub: String,
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
    // ALWAYS: The time the ID token was issued. Represented in Unix time (integer seconds).
    pub iat: u32,
    // ALWAYS: Expiration time on or after which the ID token must not be accepted. Represented in Unix time (integer seconds).
    pub exp: i64,
}

impl Payload {
    pub fn validate(&self, client_id: &str) -> bool {
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
pub struct Jwks {
    pub keys: Vec<Key>,
}

#[derive(Deserialize, PartialEq, Eq, Debug)]
pub struct Key {
    pub kty: String, // "RSA"
    #[serde(rename = "use")]
    pub usage: String, // "sig"
    pub e: String,   // "AQAB" (Is 65537 in 01 00 01 Hex and than Base64 encoded)
    pub kid: String, // "032b2ef3d2c2806157f8a9b9f4ef779834f85ada"
    pub n: String,   // "1Zdt2akTl0LcFko5ksUyL1caOq0zHO0ijzfKV8Z9vAGA1...."
    pub alg: String, // "RS256
}

use openssl::{
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Public},
    rsa::Rsa,
    sign::Verifier,
};
impl Key {
    pub fn to_rsa_public_key(&self) -> PKey<Public> {
        // Use the exponent and the modulus to create the public-key-parts
        // (Copied from https://github.com/Keats/jsonwebtoken/blob/2f25cbed0a906e091a278c10eeb6cc1cf30dc24a/src/crypto/rsa.rs)

        // n_decoded = [181, 4, 153, 152, 231, 167, 23, 71, 223, 91, 176,...
        let n_decoded = base64::decode_config(&self.n, base64::URL_SAFE)
            .expect("Could not base64 decode n (modulus)");

        // e_decoded = [1, 0, 1] (we can think about it as: 010001)
        let e_decoded = base64::decode_config(&self.e, base64::URL_SAFE)
            .expect("Could not base64 decode e (exponent)");

        let n = BigNum::from_slice(&n_decoded).expect("Could not create BigNum from decoded_n");
        let e = BigNum::from_slice(&e_decoded).expect("Could not create BigNum from decoded_e");

        PKey::from_rsa(
            Rsa::from_public_components(n, e)
                .expect("Could not create Rsa from public components (n, e)"),
        )
        .expect("Could not reate PKey from rsa")
    }
}

#[cfg(test)]
mod tests {

    use crate::jwt::Jwks;
    use crate::jwt::Key;
    use crate::jwt::{destruct, Jwt, Payload};
    use ring::signature;
    use std::ops::Add;
    use std::time::Duration;
    use time::OffsetDateTime;

    fn get_test_header() -> String {
        serde_json::json!({
            "alg": "RS256",
            "kid": "some-code-123",
            "typ": "JWT",
        })
        .to_string()
    }

    fn get_test_payload() -> String {
        // minimal Payload
        serde_json::json!({
          "iss": "https://accounts.google.com",
          "azp": "unsused",
          "aud": "291682216658-ufvd2b72f0o0ss7g3dgmjmm1jpmaqifs.apps.googleusercontent.com",
          "sub": "unsused",
          "email": "unsused",
          "email_verified": true,
          "at_hash": "unsused",
          "nonce": "unsused",
          "name": "unsused",
          "picture": "unsused",
          "given_name": "unsused",
          "family_name": "unsused",
          "locale": "unsused",
          "iat": 123,
          "exp": 123
        })
        .to_string()
    }

    #[test]
    fn can_destructure_jwt() -> serde_json::Result<()> {
        let header = get_test_header();
        let payload = get_test_payload();
        let signature = "ignored".to_string();

        let id_token = [&header, &payload, &signature]
            .iter()
            .map(|part| base64::encode_config(part, base64::URL_SAFE_NO_PAD))
            .collect::<Vec<String>>()
            .join(".");

        let expected_jwt = Jwt {
            header: base64::encode_config(header, base64::URL_SAFE_NO_PAD),
            payload: base64::encode_config(payload, base64::URL_SAFE_NO_PAD),
            // "ignored" base64 encoded (url-safe, no-pad)
            signature: "aWdub3JlZA".to_string(),
        };

        let jwt = destruct(id_token).unwrap();
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

    #[test]
    fn encodes_payload_correctly_as_base64() {
        let jwt_json = serde_json::json!({
        "iss": "https://accounts.google.com",
        "azp": "291682216658-ufvd2b72f0o0ss7g3dgmjmm1jpmaqifs.apps.googleusercontent.com",
        "aud": "291682216658-ufvd2b72f0o0ss7g3dgmjmm1jpmaqifs.apps.googleusercontent.com",
        "sub": "113024302343948371585",
        "email": "daredevdiary@gmail.com",
        "email_verified": true,
        "at_hash": "qnSaWmwNn7CepwfJQH5uFw",
        "nonce": "5171108-0780833-7163765",
        "name": "Nils Haberstroh",
        "picture": "https://lh3.googleusercontent.com/a/AATXAJz5p3_IYclXj5h6oiVKxYbQ0w23y1KtXkw2-sYM=s96-c",
        "given_name": "Nils",
        "family_name": "Haberstroh",
        "locale": "de",
        "iat": 1642362417,
        "exp": 1642366017
        }).to_string();

        let expected_payload_base64 = "eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIyOTE2ODIyMTY2NTgtdWZ2ZDJiNzJmMG8wc3M3ZzNkZ21qbW0xanBtYXFpZnMuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIyOTE2ODIyMTY2NTgtdWZ2ZDJiNzJmMG8wc3M3ZzNkZ21qbW0xanBtYXFpZnMuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTMwMjQzMDIzNDM5NDgzNzE1ODUiLCJlbWFpbCI6ImRhcmVkZXZkaWFyeUBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6InFuU2FXbXdObjdDZXB3ZkpRSDV1RnciLCJub25jZSI6IjUxNzExMDgtMDc4MDgzMy03MTYzNzY1IiwibmFtZSI6Ik5pbHMgSGFiZXJzdHJvaCIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQVRYQUp6NXAzX0lZY2xYajVoNm9pVkt4WWJRMHcyM3kxS3RYa3cyLXNZTT1zOTYtYyIsImdpdmVuX25hbWUiOiJOaWxzIiwiZmFtaWx5X25hbWUiOiJIYWJlcnN0cm9oIiwibG9jYWxlIjoiZGUiLCJpYXQiOjE2NDIzNjI0MTcsImV4cCI6MTY0MjM2NjAxN30";

        let controle_payload_base64 = base64::encode_config(&jwt_json, base64::URL_SAFE_NO_PAD);
        assert_eq!(expected_payload_base64, controle_payload_base64);

        let payload: Payload = serde_json::from_str(&jwt_json).unwrap();
        let payload_base64 = base64::encode_config(
            &serde_json::to_string(&payload).unwrap(),
            base64::URL_SAFE_NO_PAD,
        );

        assert_eq!(expected_payload_base64, payload_base64);
    }

    // Impl just for tests
    impl Jwt {
        fn sign_jwt(&mut self, private_key: Vec<u8>) -> serde_json::Result<()> {
            let alg = serde_json::json!(&self.header)["alg"].to_string();
            let header_payload_base64 = format!("{}.{}", self.header, self.payload);

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
                    header_payload_base64.as_bytes(),
                    &mut signature,
                )
                .expect("Could not sign the JWT");

            let signature_base_64 = base64::encode_config(signature, base64::URL_SAFE_NO_PAD);
            self.signature = signature_base_64;

            Ok(())
        }

        // NOTE: It is maybe not smart to first construct the JWT into an struct
        //      just tho then reparse all its pieces into base64 encoded elements again...

        // Validation of the authenticity of the ID-Token
        pub fn validate(&self, public_key: Vec<u8>) -> bool {
            // 1. Verify that the ID token is properly signed by the issuer. Google-issued tokens are
            //    signed using one of the certificates found at the URI specified in the jwks_uri
            //    metadata value of the Discovery document.
            let signature_bytes = base64::decode_config(&self.signature, base64::URL_SAFE_NO_PAD)
                .expect("Could not decode signature");

            // Get base64(header).base64(paload)
            let header_and_payload_base64 = format!("{}.{}", self.header, self.payload);

            // Create Public-Key struct from key-bytes
            let public_key = signature::UnparsedPublicKey::new(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                public_key,
            );

            // Check that the signature matches the base64_enoced header.payload
            match public_key.verify(&header_and_payload_base64.as_bytes(), &signature_bytes) {
                Ok(()) => true,
                Err(e) => {
                    eprintln!("The signature does not match the token");
                    false
                }
            }
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
            signature: "ignored".to_string(),
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

    #[test]
    fn can_construct_public_key_from_jwk() {
        let dummy_key = Key {
            kty: "unused".to_string(),
            usage: "unused".to_string(),
            // Google-Key-Exponent from jwks-uri
            n: "tQSZmOenF0ffW7BrOzL8u4r5XH0xsI3QpFYvVSCFWrBiPWDPVjfssA6uoGI6sn3aw810Er6Atv2BjeUvrFeMLkFwuRRFyE95aCSx0s-hDNtXsIOvX7LcJgQn3F3gVUPUvQDfL40DnMq0CWWpNCxNggBdok4emegiQO-C4J7aKy_ACcznsmMVtABvJDM_KpayIfWQfujsfQ8x0pggoxfPIopZLzZaMq8teEYcpVzbNvMyMopNMNPvnKMe56O_Clf_3HQBQtovHYCOK33mJmx4u1aijRMIfgoJYdVA26raLYx5_gNu_De9VWyrvknNwCSYtS0t7xIqzH2oiKtGiM9nJw".to_string(),
            kid: "unused".to_string(),
            // Google-Key-modulus from jwks-uri
            e: "AQAB".to_string(),
            alg: "unused".to_string(),
        };

        let public_key = dummy_key.to_rsa_public_key();
        let public_key_pem = public_key.public_key_to_pem().unwrap();

        // see https://8gwifi.org/jwkconvertfunctions.jsp (paste in the google jwk)
        let expected_pub_key = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtQSZmOenF0ffW7BrOzL8
u4r5XH0xsI3QpFYvVSCFWrBiPWDPVjfssA6uoGI6sn3aw810Er6Atv2BjeUvrFeM
LkFwuRRFyE95aCSx0s+hDNtXsIOvX7LcJgQn3F3gVUPUvQDfL40DnMq0CWWpNCxN
ggBdok4emegiQO+C4J7aKy/ACcznsmMVtABvJDM/KpayIfWQfujsfQ8x0pggoxfP
IopZLzZaMq8teEYcpVzbNvMyMopNMNPvnKMe56O/Clf/3HQBQtovHYCOK33mJmx4
u1aijRMIfgoJYdVA26raLYx5/gNu/De9VWyrvknNwCSYtS0t7xIqzH2oiKtGiM9n
JwIDAQAB
-----END PUBLIC KEY-----
";

        assert_eq!(expected_pub_key.as_bytes(), public_key_pem);
    }

    #[test]
    fn can_construct_public_key_from_jwk_and_varify_token() {
        let header = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImQzMzJhYjU0NWNjMTg5ZGYxMzNlZmRkYjNhNmM0MDJlYmY0ODlhYzIiLCJ0eXAiOiJKV1QifQ".to_string();
        let payload = "eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIyOTE2ODIyMTY2NTgtdWZ2ZDJiNzJmMG8wc3M3ZzNkZ21qbW0xanBtYXFpZnMuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIyOTE2ODIyMTY2NTgtdWZ2ZDJiNzJmMG8wc3M3ZzNkZ21qbW0xanBtYXFpZnMuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTMwMjQzMDIzNDM5NDgzNzE1ODUiLCJlbWFpbCI6ImRhcmVkZXZkaWFyeUBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6Imk0MGtKTGhJSDhuZ0wwSFdoQ0JfVWciLCJub25jZSI6IjMzMjQ2NjUtMjA1ODA2My0zNjM1NjY4IiwibmFtZSI6Ik5pbHMgSGFiZXJzdHJvaCIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQVRYQUp6NXAzX0lZY2xYajVoNm9pVkt4WWJRMHcyM3kxS3RYa3cyLXNZTT1zOTYtYyIsImdpdmVuX25hbWUiOiJOaWxzIiwiZmFtaWx5X25hbWUiOiJIYWJlcnN0cm9oIiwibG9jYWxlIjoiZGUiLCJpYXQiOjE2NTAyNzM0NzAsImV4cCI6MTY1MDI3NzA3MH0".to_string();
        let signature = "If_sXURNGZNZk4XvKKtH1WnT963mETOZ2Q4CE-Uc0Rrtqaz8VnKhlHS2_P9iP85t80ZjnKAd_TgfroQX2LFZQQNOh4OzLkj-1a4d-EO2J24TqSXRqSNKX13o5cd0pCvUXU6I6dK0FKtrwNnhR9n_Op89rIfLd3SxiUnfpq3uEPrBgP89fUvuOyuWj-Tplh7lFjKlUvMANOJfl78t-sDmKJHL8szgfZPSd__1O5tKAKsjGD-JhwxniIutT8Oj0xThqJuols9rdf2TZifoniJawwp7hci3-c1R6rIOMNZsCzxQxBtdupEcOmGHw_lq3ZArh-w888gR-c5rDGGANHUiQg".to_string();

        let jwt = Jwt {
            header,
            payload,
            signature,
        };

        let jwk_json = r#"{
            "keys": [
              {
                "e": "AQAB",
                "kid": "d332ab545cc189df133efddb3a6c402ebf489ac2",
                "alg": "RS256",
                "n": "pnvsf_d6daVCXm6NoBHxpIhkk345edh7GaiXl25XR4_q2ATkiZMBF8foXaa_LTyr8W5dmvqIE71p_T9ygVLMoP7YumjOimrbwB3gEV1ekI-d2rkRbCFg56bzifkAi8gdQW3pj4j-bouOSNkEAUeVSDsHst1f-sFmckZmb1Pe1bWLI-k6TXirXQpGDEZKeh1AWxillo9AWqmDXalurQt46W6rd1y2RCj5Y5zXQheNF6Il0Izc4K5RDBKkanyZ7Dq_ZFuTpVJkxPgCjN6G8cfzM0JKujWX4Zit2xCmZhVfr7hDodnNEPo1IppWNrjcfZOtA_Jh6yBlB7T8DWd1l1PvUQ",
                "use": "sig",
                "kty": "RSA"
              }
            ]
        }"#;

        let jwks: Jwks = serde_json::from_str(jwk_json).unwrap();

        let key = jwks.keys.iter().next().unwrap();
        let rsa_pub_key = key.to_rsa_public_key();

        let is_varified = jwt.verify_with_public_key(rsa_pub_key);

        assert!(is_varified);
    }
}
