use reqwest::Client;
use serde::Deserialize;

const GOOGLE_WELL_KNOWN_DOC: &str = "https://accounts.google.com/.well-known/openid-configuration";

#[derive(Debug, Deserialize)]
struct IpMetaInformation {
    issuer: String,                        //"https://accounts.google.com",
    authorization_endpoint: String,        //"https://accounts.google.com/o/oauth2/v2/auth",
    device_authorization_endpoint: String, //"https://oauth2.googleapis.com/device/code",
    token_endpoint: String,                //"https://oauth2.googleapis.com/token",
    userinfo_endpoint: String,             //"https://openidconnect.googleapis.com/v1/userinfo",
    revocation_endpoint: String,           //"https://oauth2.googleapis.com/revoke",
    jwks_uri: String,                      //"https://www.googleapis.com/oauth2/v3/certs",
    response_types_supported: Vec<String>,
    subject_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    scopes_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    claims_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
}

#[cfg(test)]
mod tests {

    use crate::meta::check_all_values;
    use crate::meta::{IpMetaInformation, GOOGLE_WELL_KNOWN_DOC};

    #[test]
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

        let code_challenge_methods_supported = vec!["plain", "S256"];

        let well_known_data = reqwest::blocking::get(GOOGLE_WELL_KNOWN_DOC)
            .expect("Could not get the well-known doc")
            .json::<IpMetaInformation>()
            .expect("Coul not turn well-known into json");

        let all_response_types_are_correct = check_all_values(
            &response_types_supported,
            &well_known_data.response_types_supported[..],
        );
        assert!(all_response_types_are_correct);
    }
}

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
