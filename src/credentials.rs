use sha2::{Sha256, Digest};

pub struct UserCredentials{
    salt: String,
    password_hash: [u8;32]
}

impl UserCredentials {
    pub fn new(salt: String, hash: [u8;32]) -> UserCredentials{
        UserCredentials {
            salt: salt,
            password_hash: hash
        }
    }
}

pub trait CredentialsStore{
    fn credentials_for(&self, name: Option<&str>) -> Option<UserCredentials>;

    fn can_login(&self, name: Option<&str>, password: &str) -> bool{
        let credentials = match self.credentials_for(name) {
            Some(credentials) => credentials,
            None => return false
        };

        let mut hasher = Sha256::new();
        hasher.update(credentials.salt);
        hasher.update(b":");
        hasher.update(password);
        let hash = hasher.finalize();
        println!("{:?}", hash);

        credentials.password_hash[..] == hash[..]
    }
}


#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use super::{CredentialsStore, UserCredentials};

    struct NoUserStore;

    impl CredentialsStore for NoUserStore {
        fn credentials_for(&self, _name: Option<&str>) -> Option<UserCredentials> {
            None
        }
    }

    #[test]
    fn test_unknown_user() {
        let store = NoUserStore{};
        assert!(! store.can_login(Some("user"), "password"));
    }

    struct AllUsersStore;

    impl CredentialsStore for AllUsersStore {
        fn credentials_for(&self, _name: Option<&str>) -> Option<UserCredentials> {
            Some(UserCredentials::new(
                "salt".to_string(),
                hex!("291e247d155354e48fec2b579637782446821935fc96a5a08a0b7885179c408b")
            ))
        }
    }

    #[test]
    fn test_wrong_password() {
        let store = AllUsersStore{};
        assert!(! store.can_login(Some("user"), "wrong"));
    }

    #[test]
    fn test_successful() {
        let store = AllUsersStore{};
        assert!(store.can_login(Some("user"), "password"));
    }

}
