use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use generic_array::GenericArray;
use generic_array::typenum::U32;
use base64::{encode_config_buf, decode_config};


pub trait AuthConfig<'a> {
    fn secret(&'a self) -> &'a [u8; 32];
}


fn sign_token<'a, T: AuthConfig<'a>>(bytes: &[u8], config: &'a T) -> GenericArray<u8, U32> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.update(b".");
    hasher.update(&config.secret());
    return hasher.finalize();
}


#[derive(Serialize, Deserialize)]
struct Token {
    expiration: u64
}

#[derive(Debug, PartialEq)]
enum VerificationError{
    FormatError,
    SignatureError,
    ExpirationError
}

impl Token {
    pub fn new(expiration: u64) -> Token {
        Token{ expiration: expiration }
    }

    pub fn generate<'a, T: AuthConfig<'a>>(&self, config: &'a T) -> String {
        let json = serde_json::to_string(self).unwrap().into_bytes();
        let signature = sign_token(&json, config);
        let config = base64::Config::new(base64::CharacterSet::Standard, false);

        let mut result = String::new();
        encode_config_buf(json, config, &mut result);
        result.push('.');
        encode_config_buf(signature, config, &mut result);

        result
    }

    pub fn verify<'a, T: AuthConfig<'a>>(value: &str, config: &'a T, time: u64) ->
            Result<(), VerificationError> {
        let b64_config = base64::Config::new(base64::CharacterSet::Standard, false);

        let pos = match value.find('.') {
            Some(pos) => pos,
            None => return Err(VerificationError::FormatError)
        };

        let token = match decode_config(&value[0..pos], b64_config) {
            Ok(token) => token,
            Err(_) => return Err(VerificationError::FormatError)
        };

        let signature = match decode_config(&value[pos + 1..], b64_config) {
            Ok(signature) => signature,
            Err(_) => return Err(VerificationError::FormatError)
        };

        if signature[..] != sign_token(&token, config)[..] {
            return Err(VerificationError::SignatureError);
        }

        match String::from_utf8(token) {
            Ok(token_json) => match serde_json::from_str::<Token>(&token_json) {
                Ok(value) => if value.expiration > time {
                    Ok(())
                } else {
                    Err(VerificationError::ExpirationError)
                },
                Err(_) => Err(VerificationError::FormatError)
            },
            Err(_) => return Err(VerificationError::FormatError)
        }
    }
}



#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use super::sign_token;
    use super::AuthConfig;
    use super::Token;
    use super::VerificationError;

    struct MockConfig {
        secret: [u8; 32]
    }

    impl MockConfig {
        pub fn new(secret: [u8; 32]) -> MockConfig {
            MockConfig{ secret: secret }
        }
    }

    impl<'a> AuthConfig<'a> for MockConfig {
        fn secret(&'a self) -> &'a [u8;32] {
            &self.secret
        }
    }

    #[test]
    fn test_signing_tokens() {
        let config = &MockConfig::new(*b"01234567890123456789012345678901");
        let signature = sign_token(b"Hello, world", config);
        assert_eq!(
            signature[..],
            hex!("e6a9533b030dba663945657efd8f2f47f5920d24ee5c74e275c3856711a1544f")[..]
        );
    }

    #[test]
    fn test_generating_token() {
        let config = &MockConfig::new(*b"01234567890123456789012345678901");
        let token = Token::new(10203040);
        assert_eq!(
            token.generate(config),
            "eyJleHBpcmF0aW9uIjoxMDIwMzA0MH0.Z8NCgEZkfzFGgAGZa0PbzcKZiZ3tu1jZzVz1ARZd0Eg"[..]
        );
    }

    fn call_verify(token: &str, time: u64) -> Result<(), VerificationError> {
        let config = &MockConfig::new(*b"01234567890123456789012345678901");
        Token::verify(token, config, time)
    }

    #[test]
    fn test_verify_no_period() {
        assert_eq!(
            call_verify("eyJleHBpcmF0aW9uIjoxMDIwMzA0M", 99999999),
            Err(VerificationError::FormatError)
        );
    }

    #[test]
    fn test_invalid_token_encoding() {
        assert_eq!(
            call_verify("eyJlабвpcmF0aW9uIjoxMDIwMzA0MH0.Z8NCgEZkfzFGgAGZa0PbzcKZiZ3tu1jZzVz1ARZd0Eg", 999999),
            Err(VerificationError::FormatError)
        );
    }

    #[test]
    fn test_invalid_signature_encoding() {
        assert_eq!(
            call_verify("eyJleHBpcmF0aW9uIjoxMDIwMzA0MH0.абвгдеZkfzFGgAGZa0PbzcKZiZ3tu1jZzVz1ARZd0Eg", 999999),
            Err(VerificationError::FormatError)
        );
    }

    #[test]
    fn test_invalid_signature() {
        assert_eq!(
            call_verify("eyJleHBpcmF0aW9uIjoxMDIwMzA0MH0.Y8NCgEZkfzFGgAGZa0PbzcKZiZ3tu1jZzVz1ARZd0Eg", 999999),
            Err(VerificationError::SignatureError)
        );
    }

    #[test]
    fn test_not_a_json() {
        assert_eq!(
            call_verify("bm90LWpzb24.5FcMWcxfA8tsY9XN1NUIsFjjQtr+V3PUGOp4MODkLdk", 999999),
            Err(VerificationError::FormatError)
        );
    }

    #[test]
    fn test_token_expired() {
        assert_eq!(
            call_verify("eyJleHBpcmF0aW9uIjoxMDIwMzA0MH0.Z8NCgEZkfzFGgAGZa0PbzcKZiZ3tu1jZzVz1ARZd0Eg", 10203060),
            Err(VerificationError::ExpirationError)
        );
    }

    #[test]
    fn test_valid_token() {
        assert_eq!(
            call_verify("eyJleHBpcmF0aW9uIjoxMDIwMzA0MH0.Z8NCgEZkfzFGgAGZa0PbzcKZiZ3tu1jZzVz1ARZd0Eg", 10203030),
            Ok(())
        );
    }
}
