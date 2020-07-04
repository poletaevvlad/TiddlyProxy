use sha2::{Sha256, Digest};
use generic_array::GenericArray;
use generic_array::typenum::U32;


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


#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use super::sign_token;
    use super::AuthConfig;

    #[test]
    fn test_signing_tokens() {
        let config = &AuthConfig::new(*b"01234567890123456789012345678901");
        let signature = sign_token(b"Hello, world", config);
        assert_eq!(
            signature[..],
            hex!("e6a9533b030dba663945657efd8f2f47f5920d24ee5c74e275c3856711a1544f")[..]
        );
    }

}
