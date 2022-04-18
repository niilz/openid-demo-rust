#![allow(unused_variables)]
use ring::signature::{self, RsaPublicKeyComponents};
use rsa::pkcs8::ToPublicKey;
use serde::{Deserialize, Serialize};
use simple_asn1::BigUint;
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
    pub fn validate_from_rsa_parts(&self, public_key: RsaPublicKeyComponents<Vec<u8>>) -> bool {
        println!("self.header: {}", self.header);
        println!("self.payload: {}", self.payload);
        println!("self.Signature {}", self.signature);
        // 1. Verify that the ID token is properly signed by the issuer. Google-issued tokens are
        //    signed using one of the certificates found at the URI specified in the jwks_uri
        //    metadata value of the Discovery document.
        let signature_bytes = base64::decode_config(&self.signature, base64::URL_SAFE_NO_PAD)
            .expect("Could not decode signature");

        // Get base64(header).base64(paload)
        let header_and_payload_base64 = self
            .header_and_payload_base64()
            .expect("Could not transform header and payload to base64");

        let n_big = rsa::BigUint::from_bytes_be(&public_key.n);
        let e_big = rsa::BigUint::from_bytes_be(&public_key.e);
        let public_key_rsa = rsa::RsaPublicKey::new(n_big, e_big).unwrap();
        let pub_key_pem = public_key_rsa.to_public_key_pem().unwrap();
        println!("PUB-KEY: {}", pub_key_pem);
        let pub_key =
            signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, pub_key_pem);
        match pub_key.verify(header_and_payload_base64.as_bytes(), &signature_bytes) {
            Ok(()) => println!("yippiiii"),
            Err(e) => println!("nope! Err: {e}"),
        }

        // Check that the signature matches the base64_enoced header.payload
        // ERROR: The VERIFY-Function does not work (it always fails)

        match public_key.verify(
            &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
            &header_and_payload_base64.as_bytes(),
            &signature_bytes,
        ) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("The signature does not match the token. Err: {e}");
                false
            }
        }
    }

    fn header_and_payload_base64(&self) -> serde_json::Result<String> {
        let head_base64 = base64::encode_config(
            serde_json::to_string(&self.header)?,
            base64::URL_SAFE_NO_PAD,
        );
        let payload_base64 = base64::encode_config(
            serde_json::to_string(&self.payload)?,
            base64::URL_SAFE_NO_PAD,
        );
        Ok(format!("{}.{}", head_base64, payload_base64))
    }
}

pub fn destruct(id_token: impl AsRef<str>) -> Result<Jwt, &'static str> {
    println!("the ID_TOKEN: {}", id_token.as_ref());
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

        // n_decoded = [181, 4, 153, 152, 231, 167, 23, 71, 223, 91, 176,...
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

    use crate::jwt::Jwks;
    use crate::jwt::Key;
    use crate::jwt::{destruct, Jwt, Payload};
    use crate::meta::IpMetaInformation;
    use ring::signature;
    use rsa::pkcs8::ToPublicKey;
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
            n: "tQSZmOenF0ffW7BrOzL8u4r5XH0xsI3QpFYvVSCFWrBiPWDPVjfssA6uoGI6sn3aw810Er6Atv2BjeUvrFeMLkFwuRRFyE95aCSx0s-hDNtXsIOvX7LcJgQn3F3gVUPUvQDfL40DnMq0CWWpNCxNggBdok4emegiQO-C4J7aKy_ACcznsmMVtABvJDM_KpayIfWQfujsfQ8x0pggoxfPIopZLzZaMq8teEYcpVzbNvMyMopNMNPvnKMe56O_Clf_3HQBQtovHYCOK33mJmx4u1aijRMIfgoJYdVA26raLYx5_gNu_De9VWyrvknNwCSYtS0t7xIqzH2oiKtGiM9nJw".to_string(),
            kid: "unused".to_string(),
            // Google-Key-modulus from jwks-uri
            e: "AQAB".to_string(),
            alg: "unused".to_string(),
        };

        let public_key = dummy_key.to_rsa_public_key();

        // in HEX (see: https://cryptii.com/pipes/base64-to-hex)
        // b5 04 99 98 e7 a7 17 47 df 5b b0 6b 3b 32 fc bb 8a f9 5c 7d 31 b0 8d d0 a4 56 2f 55 20 85 5a b0 62 3d 60 cf 56 37 ec b0 0e ae a0 62 3a b2 7d da c3 cd 74 12 be 80 b6 fd 81 8d e5 2f ac 57 8c 2e 41 70 b9 14 45 c8 4f 79 68 24 b1 d2 cf a1 0c db 57 b0 83 af 5f b2 dc 26 04 27 dc 5d e0 55 43 d4 bd 00 df 2f 8d 03 9c ca b4 09 65 a9 34 2c 4d 82 00 5d a2 4e 1e 99 e8 22 40 ef 82 e0 9e da 2b 2f c0 09 cc e7 b2 63 15 b4 00 6f 24 33 3f 2a 96 b2 21 f5 90 7e e8 ec 7d 0f 31 d2 98 20 a3 17 cf 22 8a 59 2f 36 5a 32 af 2d 78 46 1c a5 5c db 36 f3 32 32 8a 4d 30 d3 ef 9c a3 1e e7 a3 bf 0a 57 ff dc 74 01 42 da 2f 1d 80 8e 2b 7d e6 26 6c 78 bb 56 a2 8d 13 08 7e 0a 09 61 d5 40 db aa da 2d 8c 79 fe 03 6e fc 37 bd 55 6c ab be 49 cd c0 24 98 b5 2d 2d ef 12 2a cc 7d a8 88 ab 46 88 cf 67 27
        let expected_bytes_exponent = [1, 0, 1];
        let expected_bytes_modulus = [
            181, 4, 153, 152, 231, 167, 23, 71, 223, 91, 176, 107, 59, 50, 252, 187, 138, 249, 92,
            125, 49, 176, 141, 208, 164, 86, 47, 85, 32, 133, 90, 176, 98, 61, 96, 207, 86, 55,
            236, 176, 14, 174, 160, 98, 58, 178, 125, 218, 195, 205, 116, 18, 190, 128, 182, 253,
            129, 141, 229, 47, 172, 87, 140, 46, 65, 112, 185, 20, 69, 200, 79, 121, 104, 36, 177,
            210, 207, 161, 12, 219, 87, 176, 131, 175, 95, 178, 220, 38, 4, 39, 220, 93, 224, 85,
            67, 212, 189, 0, 223, 47, 141, 3, 156, 202, 180, 9, 101, 169, 52, 44, 77, 130, 0, 93,
            162, 78, 30, 153, 232, 34, 64, 239, 130, 224, 158, 218, 43, 47, 192, 9, 204, 231, 178,
            99, 21, 180, 0, 111, 36, 51, 63, 42, 150, 178, 33, 245, 144, 126, 232, 236, 125, 15,
            49, 210, 152, 32, 163, 23, 207, 34, 138, 89, 47, 54, 90, 50, 175, 45, 120, 70, 28, 165,
            92, 219, 54, 243, 50, 50, 138, 77, 48, 211, 239, 156, 163, 30, 231, 163, 191, 10, 87,
            255, 220, 116, 1, 66, 218, 47, 29, 128, 142, 43, 125, 230, 38, 108, 120, 187, 86, 162,
            141, 19, 8, 126, 10, 9, 97, 213, 64, 219, 170, 218, 45, 140, 121, 254, 3, 110, 252, 55,
            189, 85, 108, 171, 190, 73, 205, 192, 36, 152, 181, 45, 45, 239, 18, 42, 204, 125, 168,
            136, 171, 70, 136, 207, 103, 39,
        ];

        let expected_e = rsa::BigUint::from_bytes_be(&expected_bytes_exponent);
        assert_eq!(expected_e.to_bytes_be(), public_key.e);
        let expected_n = rsa::BigUint::from_bytes_be(&expected_bytes_modulus);
        assert_eq!(expected_n.to_bytes_be(), public_key.n);

        // Construct and write public key from exponent and modulus
        let public_key_big_e = rsa::BigUint::from_bytes_be(&public_key.e);
        let public_key_big_n = rsa::BigUint::from_bytes_be(&public_key.n);
        let _ = rsa::RsaPublicKey::new(public_key_big_n, public_key_big_e)
            .unwrap()
            .write_public_key_pem_file("public-key-from-components.pem");

        let public_key = fs::read_to_string("public-key-from-components.pem").unwrap();

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

        assert_eq!(expected_pub_key, public_key);
    }

    #[test]
    fn can_construct_public_key_from_jwk_with_rsa_public_key_components() {
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

        let actual_google_pem_a = "-----BEGIN CERTIFICATE-----\nMIIDJjCCAg6gAwIBAgIIGmjjgfnH1wkwDQYJKoZIhvcNAQEFBQAwNjE0MDIGA1UE\nAwwrZmVkZXJhdGVkLXNpZ25vbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTAe\nFw0yMjA0MDUxNTIxNDdaFw0yMjA0MjIwMzM2NDdaMDYxNDAyBgNVBAMMK2ZlZGVy\nYXRlZC1zaWdub24uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8KTW+pPepMtaxnTLI7pPmwcEVQw8j1tyN\nP3I73hxlR8mO21FX9EzFSC8H5zej53Ht/haszeSdihafmmYYfr8He8lu+dPN+eOi\nNoF+yqfwJ2h/WYjc3pkqaEVVbP5K6LrnJxv0XYxXD7PQNxnGT8NwEQwbonGmz0jb\n+EWbvGQI+OI3ZDxP4ws2EliejEF7VW27IIUUQMC1TlVcjIkR0OjP8xchHujxOxBO\ndfVmkHhKKO1KHPigldpAZ5Jvx5v0CDCI66IUoed2Ixp6a0R+ciRTgRdn8xdct2LR\nGr564DtdUWT6PWNXFG1U6GvPRUgzLYHyDqXzXvMoeoLdki/U9tRVAgMBAAGjODA2\nMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsG\nAQUFBwMCMA0GCSqGSIb3DQEBBQUAA4IBAQB8CuCKHRfysTxXke6rNk7PKxKiX4hh\nErJ3CqQGlTZ9bry6fZPDWI4pBFVd4Bwhn9/xCttdEmu1xGezKOKVhxyG6VUftZoG\nSILFQuOJ2bljnP8kcyyM+vtA5tPV2TwxVebtttyymvD7hb5NVP5dogDRyvjefL+u\nGKtoIrK2P6rk3pqbiHOngxOebcp+5NQluD1SG0J8QArRjY5CwhpdGlzR6bGsIefb\nqpLfonPw2mrX7BNVwm1qKvyN4p/egQLOm2WyIIPiQnZmwE7nuncncQa1XBUWeFxk\n78bU7IdmVS9YD/Rwyl2JBeM7DHXDTDOSRyv+MWAAFZ7yVeCRsDFJrE/x\n-----END CERTIFICATE-----\n";
        let actual_google_pem_b = "-----BEGIN CERTIFICATE-----\nMIIDJjCCAg6gAwIBAgIIbnk0TccKKi4wDQYJKoZIhvcNAQEFBQAwNjE0MDIGA1UE\nAwwrZmVkZXJhdGVkLXNpZ25vbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTAe\nFw0yMjA0MTMxNTIxNDlaFw0yMjA0MzAwMzM2NDlaMDYxNDAyBgNVBAMMK2ZlZGVy\nYXRlZC1zaWdub24uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCme+x/93p1pUJebo2gEfGkiGSTfjl52HsZ\nqJeXbldHj+rYBOSJkwEXx+hdpr8tPKvxbl2a+ogTvWn9P3KBUsyg/ti6aM6KatvA\nHeARXV6Qj53auRFsIWDnpvOJ+QCLyB1BbemPiP5ui45I2QQBR5VIOwey3V/6wWZy\nRmZvU97VtYsj6TpNeKtdCkYMRkp6HUBbGKWWj0BaqYNdqW6tC3jpbqt3XLZEKPlj\nnNdCF40XoiXQjNzgrlEMEqRqfJnsOr9kW5OlUmTE+AKM3obxx/MzQkq6NZfhmK3b\nEKZmFV+vuEOh2c0Q+jUimlY2uNx9k60D8mHrIGUHtPwNZ3WXU+9RAgMBAAGjODA2\nMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsG\nAQUFBwMCMA0GCSqGSIb3DQEBBQUAA4IBAQBxeBEVTkb5Hbys3MOMc7drCGFoAbHy\n2ahQ7+nIyRvCnCvEG0odoKA5zo2GPIzmk5wfQ/xDC2MwX68rMYRFxRNQYxoyaGB0\naGwtQRPdubAKs5HdxlLPF2jVKoEEtupWoruuf3razHNIxlg6MdF3OuEzTHxeJpjX\njA/ccn9kXEBXl9SBVY44cjqx+tXlqc+ddkByBx8dPw2x34nd55mqOPhJuIWBrtIP\nu/I2nbYx3tT54H7dEvvC6nc2Z9Iogh0u+d77AkLSw2ZHa5bjBShtmKj+l8VDEERH\nLWnTPz7mR7KLvwTCpK9OMVjX9ef5HXipkObLpSeiaqhrOs2gZWLoB9ha\n-----END CERTIFICATE-----\n";
        let jwks: Jwks = serde_json::from_str(jwk_json).unwrap();
        println!("n: {:?}", jwks);

        let key = jwks.keys.iter().next().unwrap();
        let rsa_pub_key = key.to_rsa_public_key();

        let n_big = rsa::BigUint::from_bytes_be(&rsa_pub_key.n);
        let e_big = rsa::BigUint::from_bytes_be(&rsa_pub_key.e);
        let public_key_rsa = rsa::RsaPublicKey::new(n_big, e_big).unwrap();
        let pub_key_pem = public_key_rsa.to_public_key_pem().unwrap();
        println!("rsa_pub_key: {}", pub_key_pem);

        use google_jwt_verify::Client;
        let client_id = "291682216658-ufvd2b72f0o0ss7g3dgmjmm1jpmaqifs.apps.googleusercontent.com";
        let token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImQzMzJhYjU0NWNjMTg5ZGYxMzNlZmRkYjNhNmM0MDJlYmY0ODlhYzIiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIyOTE2ODIyMTY2NTgtdWZ2ZDJiNzJmMG8wc3M3ZzNkZ21qbW0xanBtYXFpZnMuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIyOTE2ODIyMTY2NTgtdWZ2ZDJiNzJmMG8wc3M3ZzNkZ21qbW0xanBtYXFpZnMuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTMwMjQzMDIzNDM5NDgzNzE1ODUiLCJlbWFpbCI6ImRhcmVkZXZkaWFyeUBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IkV6Uzd6bWVzVDAwN0o2TEFYQ2dNN1EiLCJub25jZSI6IjY3ODY0MDQtMjUwMDY0NS0xNzcxODU0IiwibmFtZSI6Ik5pbHMgSGFiZXJzdHJvaCIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQVRYQUp6NXAzX0lZY2xYajVoNm9pVkt4WWJRMHcyM3kxS3RYa3cyLXNZTT1zOTYtYyIsImdpdmVuX25hbWUiOiJOaWxzIiwiZmFtaWx5X25hbWUiOiJIYWJlcnN0cm9oIiwibG9jYWxlIjoiZGUiLCJpYXQiOjE2NTAyNjU0NjYsImV4cCI6MTY1MDI2OTA2Nn0.UP4smfJztaR5DoY01bFM6SrlX_26P7p8nEWjm3TuqXIb0mUGpQx8rR3UmzKYEddNPIdicKZJFAYm4Y9-fJ93xjn1Tb8tHl4suKIcbXLFeF9lNLzF5MW2AcydCRe6fqnl7ZKZb9zI9qSzcl1NDIUbJK23H8wQBmkYOkCU449T0U6s_KRacav_kMw6RTFYyEEOXi1D3HvsApAT2nGPUVtfcAdXKhLg_aDV8ybNWO8vLCBmbftAHYMcpTX7f-8kWI4-C9fGcrZ_-JO56aYJQk3rcnJzK2e2lY3uWIakcngzZN2wjJjgzZOwz1Ne4vGb_FCGF_L_R5B85Y537_dIgNdMZQ";

        let client = Client::new(&client_id);
        let token = client.verify_id_token(&token);
        match token {
            Ok(id_payload) => println!(
                "This lib works! Email: {}",
                id_payload.get_payload().get_name()
            ),
            Err(e) => println!("outschiii from lib: {e:?}"),
        }

        let expected_pem = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1YWUM8Y5UExSfXsBrF6o
ACI48nITxDf07CiYKn/VTbLRlpXX1AfNtQhrjm+jPjC16qXnGCBhdlZHdCycfezo
Mg8svo41U7YIVLP5G5H6f7VxAEglmV5IGc0kj35//qmqy3t1Eug/iqxCOyRlcDEL
Q75MNOhYFQtjeEtLuw4ErpPpOeYVX71vOH3Q9epItMM0n18FXW5Dd6BkCiHvMkb5
eSHOH07J0h+MkRF133R+YSPPgDlqLeRxdjDo2rwqKFsOa68edzconVcETWR2YSoF
tangVd+IBhzFrax8gyVsntKpmbg8XyJZU2vtgMiTdP0wAjAe8gy78Dg1WIOVOe58
lQIDAQAB
-----END PUBLIC KEY-----";

        //assert_eq!(expected_pem, pub_key_pem.trim_end());

        let header = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImQzMzJhYjU0NWNjMTg5ZGYxMzNlZmRkYjNhNmM0MDJlYmY0ODlhYzIiLCJ0eXAiOiJKV1QifQ";
        let payload = "eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIyOTE2ODIyMTY2NTgtdWZ2ZDJiNzJmMG8wc3M3ZzNkZ21qbW0xanBtYXFpZnMuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIyOTE2ODIyMTY2NTgtdWZ2ZDJiNzJmMG8wc3M3ZzNkZ21qbW0xanBtYXFpZnMuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTMwMjQzMDIzNDM5NDgzNzE1ODUiLCJlbWFpbCI6ImRhcmVkZXZkaWFyeUBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IldEdF9MRUlsNFFORV8yNVppXy1qQ3ciLCJub25jZSI6Ijc1ODg2MjYtMjA3NDExNi02NzA2MTM0IiwibmFtZSI6Ik5pbHMgSGFiZXJzdHJvaCIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQVRYQUp6NXAzX0lZY2xYajVoNm9pVkt4WWJRMHcyM3kxS3RYa3cyLXNZTT1zOTYtYyIsImdpdmVuX25hbWUiOiJOaWxzIiwiZmFtaWx5X25hbWUiOiJIYWJlcnN0cm9oIiwibG9jYWxlIjoiZGUiLCJpYXQiOjE2NDk5MzUxMzEsImV4cCI6MTY0OTkzODczMX0";
        let signature = "JoEW1ehJ8-hUV22oWNA_iVHjc75lmEY-9KJ71drz9udB_UcWKtLVKsbRNNGBec8sdBNkpbsWvmNTv4nSdnsA-Uwb35twBKqSyxJDSAElvnd3_7y0RMYIbFn-rmPdW58IApxzVhlfQbjBQNQMjF5YdIEP-BbxIfiBLg19PrGWwrVNhrG_Y_BbrjdS4-7903mGqO_RFaBCTvbPn7dZoJMZrlMDZPumyIdHeFGa4L2dbf6kKurfZp3sct899VFhjaVNgyHVGOUr7xRFrsQnfzj4jy4hOmXU8msKbxjEgX0s8eRmnae8YnTBwoycLLqrv1K9-bVx_LwisvcoCeXgNaQIcQ";

        let signature_bytes = base64::decode_config(signature, base64::URL_SAFE_NO_PAD).unwrap();

        let header_payload = format!("{header}.{payload}");
        println!("{header_payload}.{signature}");

        let pub_key_a = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            //pub_key_pem,
            actual_google_pem_a,
        );

        let pub_key_b = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            //pub_key_pem,
            actual_google_pem_b,
        );

        match pub_key_a.verify(header_payload.as_bytes(), &signature_bytes) {
            Ok(()) => println!("It worked"),
            Err(e) => println!("nooope: {e}"),
        }

        match pub_key_b.verify(header_payload.as_bytes(), &signature_bytes) {
            Ok(()) => println!("It worked"),
            Err(e) => println!("nooope: {e}"),
        }
    }
}
