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

trait InnerStringer
where
    Self: Sized + IntoIterator<Item = &'static str>,
{
    fn stringer(self) -> Vec<String> {
        self.into_iter().map(|s| s.to_string()).collect()
    }
}

impl InnerStringer for Vec<&'static str> {}

#[cfg(test)]
mod tests {

    use crate::meta::{IpMetaInformation, GOOGLE_WELL_KNOWN_DOC};
    use serde_json::from_str;

    #[test]
    fn can_read_well_known_document() {
        let response_types_supported = vec![
            "code",
            "token",
            "id_token",
            "code token",
            "code id_token",
            "token id_token",
            "code token id_token",
            "none",
        ];
        let subject_types_supported = vec!["public"];
        let id_token_signing_alg_values_supported = vec!["RS256"];
        let scopes_supported = vec!["openid", "email", "profile"];
        let token_endpoint_auth_methods_supported =
            vec!["client_secret_post", "client_secret_basic"];

        let claims_supported = vec![
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

        println!("response: {:?}", well_known_data);

        assert!(true);
    }
}
