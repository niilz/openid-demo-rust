use std::str::from_utf8;

#[derive(Debug, PartialEq, Eq)]
pub struct Jwt {
    pub header: String,
    pub payload: String,
    pub signature: String,
}

pub fn destruct_jwt(id_token: &str) -> Jwt {
    let dot_idx = id_token.chars().position(|c| c == '.').unwrap();
    let (header, payload_sig) = id_token.split_at(dot_idx);
    println!("payload_sig: {:?}", payload_sig);
    println!();
    let dot_idx = payload_sig
        .strip_prefix('.')
        .unwrap()
        .chars()
        .position(|c| c == '.')
        .unwrap();
    let (payload, signature) = payload_sig.split_at(dot_idx);

    println!("ID-TOKEN-Header: {:?}", header);
    println!();
    let header = base64::decode(header.trim()).unwrap();
    let header = from_utf8(&header).unwrap().to_string();
    println!("Decoded Token: {:?}", header);
    println!();

    println!("ID-TOKEN-payload: {:?}", payload);
    println!();
    let payload = base64::decode(payload.strip_prefix('.').unwrap().trim()).unwrap();
    let payload = from_utf8(&payload).unwrap().to_string();
    println!("Decoded payload: {:?}", payload);
    println!();

    Jwt {
        header,
        payload,
        signature: "sig".to_string(),
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
