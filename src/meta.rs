use crate::jwt::{Jwks, Key};
use serde::Deserialize;

pub const GOOGLE_WELL_KNOWN_DOC: &str =
    "https://accounts.google.com/.well-known/openid-configuration";

// TODO: Construct it with default values at compile time
//       Or init it on startup and cache it
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct IpMetaInformation {
    issuer: String,
    authorization_endpoint: String,
    device_authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    revocation_endpoint: String,
    jwks_uri: String,
    response_types_supported: Vec<String>,
    subject_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    scopes_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    claims_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
}

impl IpMetaInformation {
    pub async fn get_jwks(&self) -> Result<Vec<Key>, &'static str> {
        match reqwest::get(&self.jwks_uri).await {
            Ok(jwks_res) => match jwks_res.json::<Jwks>().await {
                Ok(jwks) => Ok(jwks.keys),
                Err(_) => Err("Could not transform well_known_information into IpMetaInformation"),
            },
            Err(_) => Err("Could not retrieve IP-Meta-Data from well_known document"),
        }
    }
}

pub async fn get_ip_meta_information() -> Result<IpMetaInformation, &'static str> {
    match reqwest::get(GOOGLE_WELL_KNOWN_DOC).await {
        Ok(well_known_res) => match well_known_res.json::<IpMetaInformation>().await {
            Ok(ip_meta_info) => Ok(ip_meta_info),
            Err(_) => Err("Could not transform well_known_information into IpMetaInformation"),
        },
        Err(_) => Err("Could not retrieve IP-Meta-Data from well_known document"),
    }
}

#[cfg(test)]
mod tests {

    use crate::meta::{IpMetaInformation, GOOGLE_WELL_KNOWN_DOC};

    fn check_all_values(expected_meta_data: &[&str], actual_meta_data: &[impl AsRef<str>]) -> bool {
        for expected in expected_meta_data.iter() {
            if !actual_meta_data
                .iter()
                .any(|actual| &actual.as_ref() == expected)
            {
                return false;
            }
        }
        return true;
    }

    #[test]
    #[ignore = "real web request to google shouldn't always be performed"]
    fn can_read_well_known_document() {
        let response_types_supported = [
            "code",
            "token",
            "id_token",
            "code token",
            "code id_token",
            "token id_token",
            "code token id_token",
            "none",
        ];
        let subject_types_supported = ["public"];
        let id_token_signing_alg_values_supported = ["RS256"];
        let scopes_supported = ["openid", "email", "profile"];
        let token_endpoint_auth_methods_supported = ["client_secret_post", "client_secret_basic"];

        let claims_supported = [
            "aud",
            "email",
            "email_verified",
            "exp",
            "family_name",
            "given_name",
            "iat",
            "iss",
            "locale",
            "name",
            "picture",
            "sub",
        ];

        let code_challenge_methods_supported = ["plain", "S256"];

        // Fetch acutal Meta-Data of the IP from the internet
        let well_known_data = reqwest::blocking::get(GOOGLE_WELL_KNOWN_DOC)
            .expect("Could not get the well-known doc")
            .json::<IpMetaInformation>()
            .expect("Coul not turn well-known into json");

        // Check that all our expected/hard-coded values align with the
        // data from the online document
        // TODO: Don't hard code everything, but add a cache layer
        let all_response_types_are_correct = check_all_values(
            &response_types_supported,
            &well_known_data.response_types_supported[..],
        );
        assert!(all_response_types_are_correct);

        let all_subject_types_are_correct = check_all_values(
            &subject_types_supported,
            &well_known_data.subject_types_supported[..],
        );
        assert!(all_subject_types_are_correct);

        let all_id_token_signing_algs_are_correct = check_all_values(
            &id_token_signing_alg_values_supported,
            &well_known_data.id_token_signing_alg_values_supported[..],
        );
        assert!(all_id_token_signing_algs_are_correct);

        let all_scopes_supported_are_correct =
            check_all_values(&scopes_supported, &well_known_data.scopes_supported[..]);
        assert!(all_scopes_supported_are_correct);

        let all_token_endpoint_auth_methods_are_correct = check_all_values(
            &token_endpoint_auth_methods_supported,
            &well_known_data.token_endpoint_auth_methods_supported[..],
        );
        assert!(all_token_endpoint_auth_methods_are_correct);

        let all_claims_supported_are_correct =
            check_all_values(&claims_supported, &well_known_data.claims_supported[..]);
        assert!(all_claims_supported_are_correct);

        let all_code_challenge_methods_supported_are_correct = check_all_values(
            &code_challenge_methods_supported,
            &well_known_data.code_challenge_methods_supported,
        );
        assert!(all_code_challenge_methods_supported_are_correct);

        // Check the single-value fields
        assert_eq!(well_known_data.issuer, "https://accounts.google.com");
        assert_eq!(
            well_known_data.authorization_endpoint,
            "https://accounts.google.com/o/oauth2/v2/auth"
        );
        assert_eq!(
            well_known_data.device_authorization_endpoint,
            "https://oauth2.googleapis.com/device/code"
        );
        assert_eq!(
            well_known_data.token_endpoint,
            "https://oauth2.googleapis.com/token"
        );
        assert_eq!(
            well_known_data.userinfo_endpoint,
            "https://openidconnect.googleapis.com/v1/userinfo"
        );
        assert_eq!(
            well_known_data.revocation_endpoint,
            "https://oauth2.googleapis.com/revoke"
        );
        assert_eq!(
            well_known_data.jwks_uri,
            "https://www.googleapis.com/oauth2/v3/certs"
        );
    }
}
