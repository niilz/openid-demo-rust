#[derive(Debug, PartialEq, Eq)]
pub struct Jwt {
    pub header: String,
    pub payload: String,
    pub signature: String,
}

pub fn destruct_jwt(id_token: &str) -> Jwt {
    let mut token_parts = id_token.split('.');
    let header = token_parts.next().unwrap().to_string();
    let payload = token_parts.next().unwrap().to_string();
    let signature = token_parts.next().unwrap().to_string();

    Jwt {
        header,
        payload,
        signature,
    }
}

#[cfg(test)]
mod tests {
    use crate::jwt::{destruct_jwt, Jwt};

    #[test]
    fn can_destructure_jwt() {
        let id_token = "header-stuff-algo-256.payload-12345-claims.sIgNaTuRe";

        let expected_jwt = Jwt {
            header: "header-stuff-algo-256".to_string(),
            payload: "payload-12345-claims".to_string(),
            signature: "sIgNaTuRe".to_string(),
        };

        let jwt = destruct_jwt(id_token);
        assert_eq!(expected_jwt, jwt);
    }
}
