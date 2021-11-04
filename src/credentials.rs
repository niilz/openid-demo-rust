use std::env;

pub struct Credentials {
    client_id: String,
    client_secret: String,
}

impl Credentials {
    pub fn init() -> Self {
        let client_id = load_env("CLIENT_ID");
        let client_secret = load_env("CLIENT_SECRET");
        Credentials {
            client_id,
            client_secret,
        }
    }
}

fn load_env(env_var: &str) -> String {
    match env::var(env_var) {
        Ok(val) => val,
        Err(_) => panic!("Please define environment variable: '{}' (get it from google-app-credentials-dashboard)", env_var),
    }
}

#[cfg(test)]
mod tests {
    use crate::credentials::load_env;
    use std::env;

    #[test]
    fn can_load_credentials() {
        // Don't use this Env-Vars twice in the tests because they run in parallel
        env::set_var("DUMMY_VAR", "super-secret-id");
        let expected = "super-secret-id".to_string();
        assert_eq!(expected, load_env("DUMMY_VAR"));
        env::remove_var("DUMMY_VAR");
    }
}
