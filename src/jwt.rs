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
