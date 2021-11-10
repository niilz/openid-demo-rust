use serde::Deserialize;

#[derive(Debug, PartialEq, Eq, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: u32,
    pub id_token: String,
    pub scope: String,
    pub token_type: String,
    // Only present if 'access_type' was set to 'offline'
    pub refresh_token: Option<String>,
}

#[cfg(test)]
mod tests {
    use crate::response::TokenResponse;
    use rocket::serde::json::{from_str, serde_json::json};

    #[test]
    fn can_deserialize_token_response() {
        let serialized_token_response = json!({
            "access_token": "acc-ess-token-123",
            "expires_in": 123456,
            "id_token": "id-token-456",
            "scope": "openid email",
            "token_type": "Bearer",
            // Notice that the refresh_token is not set
        })
        .to_string();

        let expected_deserialized_token_response = TokenResponse {
            access_token: "acc-ess-token-123".to_string(),
            expires_in: 123456,
            id_token: "id-token-456".to_string(),
            scope: "openid email".to_string(),
            token_type: "Bearer".to_string(),
            refresh_token: None,
        };

        let deserialized_token = from_str::<TokenResponse>(&serialized_token_response).unwrap();
        assert_eq!(expected_deserialized_token_response, deserialized_token);
    }
}
