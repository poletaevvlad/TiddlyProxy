use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use generic_array::GenericArray;
use generic_array::typenum::U32;
use base64::encode_config_buf;


struct AuthConfig {
    secret: [u8; 32]
}

impl AuthConfig {
    pub fn new(secret: [u8; 32]) -> AuthConfig {
        AuthConfig{ secret: secret }
    }
}


fn sign_token(bytes: &[u8], config: &AuthConfig) -> GenericArray<u8, U32> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.update(b".");
    hasher.update(&config.secret);
    return hasher.finalize();
}


#[derive(Serialize, Deserialize)]
struct Token {
    expiration: u64
}

impl Token {
    pub fn new(expiration: u64) -> Token {
        Token{ expiration: expiration }
    }

    pub fn generate(&self, config: &AuthConfig) -> String {
        let json = serde_json::to_string(self).unwrap().into_bytes();
        let signature = sign_token(&json, config);
        let config = base64::Config::new(base64::CharacterSet::Standard, false);

        let mut result = String::new();
        encode_config_buf(json, config, &mut result);
        result.push('.');
        encode_config_buf(signature, config, &mut result);

        result
    }
}



#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use super::sign_token;
    use super::AuthConfig;
    use super::Token;

    #[test]
    fn test_signing_tokens() {
        let config = &AuthConfig::new(*b"01234567890123456789012345678901");
        let signature = sign_token(b"Hello, world", config);
        assert_eq!(
            signature[..],
            hex!("e6a9533b030dba663945657efd8f2f47f5920d24ee5c74e275c3856711a1544f")[..]
        );
    }

    #[test]
    fn test_generating_token() {
        let config = &AuthConfig::new(*b"01234567890123456789012345678901");
        let token = Token::new(10203040);
        assert_eq!(
            token.generate(config),
            "eyJleHBpcmF0aW9uIjoxMDIwMzA0MH0.Z8NCgEZkfzFGgAGZa0PbzcKZiZ3tu1jZzVz1ARZd0Eg"[..]
        );
    }
}
