#![allow(unused_variables)]
use ring::signature::{self, RsaPublicKeyComponents};
use serde::{Deserialize, Serialize};
use simple_asn1::BigUint;
use time::OffsetDateTime;

#[allow(dead_code)]
const ALLOWED_ISSUERS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Jwt {
    pub header: Header,
    pub payload: Payload,
    pub signature: String,
}

impl Jwt {
    // NOTE: It is maybe not smart to first construct the JWT into an struct
    //      just tho then reparse all its pieces into base64 encoded elements again...

    // Validation of the authenticity of the ID-Token
    pub fn validate_from_rsa_parts(&self, public_key: RsaPublicKeyComponents<Vec<u8>>) -> bool {
        // 1. Verify that the ID token is properly signed by the issuer. Google-issued tokens are
        //    signed using one of the certificates found at the URI specified in the jwks_uri
        //    metadata value of the Discovery document.
        let signature_bytes = base64::decode(&self.signature).expect("Could not decode signature");

        // Get base64(header).base64(paload)
        let header_and_payload_base64 = self
            .header_and_payload_base64()
            .expect("Could not transform header and payload to base64");

        // Check that the signature matches the base64_enoced header.payload
        // ERROR: The VERIFY-Function does not work (it always fails)
        match public_key.verify(
            &signature::RSA_PKCS1_2048_8192_SHA512,
            &header_and_payload_base64.as_bytes(),
            &signature_bytes,
        ) {
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

pub fn destruct(id_token: impl AsRef<str>) -> Result<Jwt, &'static str> {
    let parts = get_token_parts(id_token.as_ref());
    if let [header, payload, signature] = &parts[..] {
        return Ok(Jwt {
            header: serde_json::from_str(header).unwrap(),
            payload: serde_json::from_str(payload).unwrap(),
            signature: signature.to_string(),
        });
    };
    Err("Token has unsupported format")
}

// TODO: Get rid of these horrible mutable variables
// The entire thing should be rewritten
fn get_token_parts(id_token: &str) -> Vec<String> {
    let mut token_parts = id_token.split('.');
    let mut header_payload_signature: Vec<String> = token_parts
        .clone()
        .take(2)
        .filter_map(|part| base64::decode(part).ok())
        .filter_map(|part| String::from_utf8(part).ok())
        .collect();
    header_payload_signature.push(token_parts.last().unwrap().to_string());
    header_payload_signature
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

impl Key {
    pub fn to_rsa_public_key(&self) -> RsaPublicKeyComponents<Vec<u8>> {
        // Use the exponent and the modulus to create the public-key-parts
        // (Copied from https://github.com/Keats/jsonwebtoken/blob/2f25cbed0a906e091a278c10eeb6cc1cf30dc24a/src/crypto/rsa.rs)

        // n_decoded = [180, 44, 33, 28, 236,...
        let n_decoded = base64::decode_config(self.n.clone(), base64::URL_SAFE_NO_PAD)
            .expect("Could not base64 decode n (modulus)");

        // e_decoded = [1, 0, 1] (we can think about it as: 010001)
        let e_decoded = base64::decode_config(self.e.clone(), base64::URL_SAFE_NO_PAD)
            .expect("Could not base64 decode e (exponent)");

        let n_be = BigUint::from_bytes_be(&n_decoded).to_bytes_be();
        let e_be = BigUint::from_bytes_be(&e_decoded).to_bytes_be();

        RsaPublicKeyComponents { n: n_be, e: e_be }
    }
}

#[cfg(test)]
mod tests {

    use crate::jwt::Header;
    use crate::jwt::Jwks;
    use crate::jwt::Key;
    use crate::jwt::{destruct, get_token_parts, Jwt, Payload};
    use ring::signature;
    use simple_asn1::BigUint;
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
        let signature = "signature";

        let header_en = base64::encode(header);
        let payload_en = base64::encode(payload);
        let signature = base64::encode(signature);

        let id_token = format!("{}.{}.{}", header_en, payload_en, signature);

        let expected_parts = vec![
            "header-stuff-algo-256",
            "payload-12345-claims",
            "c2lnbmF0dXJl",
        ];
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
            // "ignored" base64 encoded
            signature: "aWdub3JlZA==".to_string(),
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
            let signature_bytes =
                base64::decode(&self.signature).expect("Could not decode signature");

            // Get base64(header).base64(paload)
            let header_and_payload_base64 = self
                .header_and_payload_base64()
                .expect("Could not transform header and payload to base64");

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
            e: "tCwhHOxX_ylh5kVwfVqW7QIBTIsPjkjCjVCppDrynuF_3msEdtEaG64eJUz84ODFNMCC0BQ57G7wrKQVWkdSDxWUEqGk2BixBiHJRWZdofz1WOBTdPVicvHW5Zl_aIt7uXWMdOp_SODw-O2y2f05EqbFWFnR2-1y9K8KbiOp82CD72ny1Jbb_3PxTs2Z0F4ECAtTzpDteaJtjeeueRjr7040JAjQ-5fpL5D1g8x14LJyVIo-FL_y94NPFbMp7UCi69CIfVHXFO8WYFz949og-47mWRrID5lS4zpx-QLuvNhUb_lSqmylUdQB3HpRdOcYdj3xwy4MHJuu7tTaf0AmCQ".to_string(),
            kid: "unused".to_string(),
            // Google-Key-modulus from jwks-uri
            n: "d98f49bc6ca4581eae8dfadd494fce10ea23aab0".to_string(),
            alg: "unused".to_string(),
        };

        let public_key = dummy_key.to_rsa_public_key();

        let expected_bytes_exponent = [
            180, 44, 33, 28, 236, 87, 255, 41, 97, 230, 69, 112, 125, 90, 150, 237, 2, 1, 76, 139,
            15, 142, 72, 194, 141, 80, 169, 164, 58, 242, 158, 225, 127, 222, 107, 4, 118, 209, 26,
            27, 174, 30, 37, 76, 252, 224, 224, 197, 52, 192, 130, 208, 20, 57, 236, 110, 240, 172,
            164, 21, 90, 71, 82, 15, 21, 148, 18, 161, 164, 216, 24, 177, 6, 33, 201, 69, 102, 93,
            161, 252, 245, 88, 224, 83, 116, 245, 98, 114, 241, 214, 229, 153, 127, 104, 139, 123,
            185, 117, 140, 116, 234, 127, 72, 224, 240, 248, 237, 178, 217, 253, 57, 18, 166, 197,
            88, 89, 209, 219, 237, 114, 244, 175, 10, 110, 35, 169, 243, 96, 131, 239, 105, 242,
            212, 150, 219, 255, 115, 241, 78, 205, 153, 208, 94, 4, 8, 11, 83, 206, 144, 237, 121,
            162, 109, 141, 231, 174, 121, 24, 235, 239, 78, 52, 36, 8, 208, 251, 151, 233, 47, 144,
            245, 131, 204, 117, 224, 178, 114, 84, 138, 62, 20, 191, 242, 247, 131, 79, 21, 179,
            41, 237, 64, 162, 235, 208, 136, 125, 81, 215, 20, 239, 22, 96, 92, 253, 227, 218, 32,
            251, 142, 230, 89, 26, 200, 15, 153, 82, 227, 58, 113, 249, 2, 238, 188, 216, 84, 111,
            249, 82, 170, 108, 165, 81, 212, 1, 220, 122, 81, 116, 231, 24, 118, 61, 241, 195, 46,
            12, 28, 155, 174, 238, 212, 218, 127, 64, 38, 9,
        ];
        let expected_bytes_modulus = [
            119, 223, 31, 227, 214, 220, 233, 198, 184, 231, 205, 94, 105, 239, 29, 125, 167, 93,
            227, 222, 31, 113, 237, 116, 121, 173, 183, 105, 166, 244,
        ];

        assert_eq!(
            BigUint::from_bytes_be(&expected_bytes_exponent).to_bytes_be(),
            public_key.e
        );
        assert_eq!(
            BigUint::from_bytes_be(&expected_bytes_modulus).to_bytes_be(),
            public_key.n
        );
    }
}
