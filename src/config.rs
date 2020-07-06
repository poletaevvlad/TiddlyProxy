use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;
use http::uri::Uri;
use std::collections::HashMap;
use clap::{ArgMatches};
use generic_array::{GenericArray, ArrayLength};
use generic_array::typenum::U32;
use crate::auth::AuthConfig;
use crate::credentials::{UserCredentials, CredentialsStore};


#[derive(Debug)]
pub struct ProxyConfig {
    remote_uri: Uri,
    secret: GenericArray<u8, U32>,
    users: HashMap<Option<String>, UserCredentials>,
    socker_addr: SocketAddr
}

impl ProxyConfig {
    pub fn from_values(
        wiki_url: &str, secret: &str, users: &str,
        host: Option<&str>, port: Option<&str>
    ) -> Result<ProxyConfig, (&'static str, String)> {
        let remote_uri = match parse_wiki_uri(wiki_url) {
            Ok(uri) => uri,
            Err(error) => return Err(("wiki_url", error))
        };

        let secret = match parse_hex_string::<U32>(secret) {
            Ok(buffer) => buffer,
            Err(error) => return Err(("secret", error))
        };

        let users = match parse_credentials(users) {
            Ok(users) => {
                let mut map = HashMap::new();
                for (username, credentials) in users {
                    map.insert(username, credentials);
                }
                map
            },
            Err(error) => return Err(("users", error))
        };

        let port = match port.map(parse_port) {
            Some(Ok(port)) => port,
            Some(Err(error)) => return Err(("port", error)),
            None => 3000
        };

        let host = match host.map(parse_host) {
            Some(Ok(addr)) => addr,
            Some(Err(error)) => return Err(("host", error)),
            None => IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
        };

        Ok(ProxyConfig{
            remote_uri: remote_uri,
            secret: secret,
            users: users,
            socker_addr: SocketAddr::new(host, port)
        })
    }

    pub fn from_args<'a>(matches: &ArgMatches<'a>) -> Result<ProxyConfig, (&'static str, String)> {
        ProxyConfig::from_values(
            matches.value_of("wiki_url").unwrap(),
            matches.value_of("secret").unwrap(),
            matches.value_of("users").unwrap(),
            matches.value_of("host"),
            matches.value_of("port")
        )
    }

    pub fn remote_uri(&self) -> &Uri {
        &self.remote_uri
    }

    pub fn socket_addr(&self) -> &SocketAddr {
        &self.socker_addr
    }
}

impl<'a> AuthConfig<'a> for ProxyConfig {
    fn secret(&'a self) -> &'a [u8;32] {
        self.secret.as_ref()
    }
}

impl CredentialsStore for ProxyConfig {
    fn credentials_for<'a>(&'a self, name: Option<&str>) -> Option<&'a UserCredentials>{
        self.users.get(&name.map(String::from))
    }
}

pub struct ArcAuthProxyConfig{
    obj: Arc<ProxyConfig>
}

impl ArcAuthProxyConfig{
    pub fn new(obj: Arc<ProxyConfig>) -> ArcAuthProxyConfig {
        ArcAuthProxyConfig{ obj: obj }
    }
}

impl<'a> AuthConfig<'a> for ArcAuthProxyConfig {
    fn secret(&'a self) -> &'a [u8; 32] {
        self.obj.secret()
    }
}



pub fn parse_wiki_uri(uri: &str) -> Result<Uri, String> {
    match uri.parse::<Uri>() {
        Ok(uri) => {
            let schema = uri.scheme_str();
            if schema != None && schema != Some("http") {
                return Err(format!("Protocol not supported: {}", uri.scheme_str().unwrap()))
            };

            let authority = match uri.authority() {
                None => return Err(String::from("Missing authority")),
                Some(authority) => authority.clone()
            };

            if uri.query() != None {
                return Err(String::from("URL cannot contain a query"));
            }

            Ok(Uri::builder()
                .scheme("http")
                .authority(authority)
                .path_and_query(uri.path())
                .build()
                .unwrap())
        },
        Err(_) => Err(format!("Cannot parse url: {}", uri))
    }
}


fn parse_hex_string<N: ArrayLength<u8>>(value: &str) -> Result<GenericArray<u8, N>, String> {
    let mut result = GenericArray::<u8, N>::default();
    let expected_length = result.len() * 2;

    if value.len() < expected_length {
        return Err(format!("String is too short, {} hex digits expected", expected_length))
    }else if value.len() > expected_length {
        return Err(format!("String is too long, {} hex digits expected", expected_length))
    }

    for (i, c) in value.chars().enumerate() {
        match c.to_digit(16) {
            Some(digit) => result[i / 2] = result[i / 2] << 4 | (digit as u8),
            None =>  return Err(format!("Invalid character at position {}", i + 1))
        }
    }
    Ok(result)
}

fn parse_credentials_part(value: &str) -> Result<(Option<String>, UserCredentials), String> {
    // Format: [<username>]:<salt>:<password>
    let components: Vec<&str> = value.trim().split(":").collect();
    if components.len() != 3 {
        return Err("Wrong number of components".to_string())
    }

    let username = if components[0].len() > 0 {
        Some(components[0])
    } else {
        None
    };

    let salt = components[1];
    if salt.len() < 5 {
        return Err("The value for salt is too short".to_string());
    }

    let password_hash = match parse_hex_string::<U32>(components[2]) {
        Ok(buffer) => buffer.into(),
        Err(message) => return Err(format!("Password hash is not valid ({})", message))
    };

    Ok((username.map(String::from), UserCredentials::new(salt.to_string(), password_hash)))
}

fn parse_credentials(value: &str) -> Result<Vec<(Option<String>, UserCredentials)>, String> {
    let mut result = Vec::<(Option<String>, UserCredentials)>::new();
    let parts: Vec<&str> = value.split(';').collect();
    for part in parts.iter() {
        match parse_credentials_part(part) {
            Ok((username, credentials)) => {
                if username == None && parts.len() > 1 {
                    return Err("User without a username must be the only user".to_string());
                }
                result.push((username, credentials))
            },
            Err(error) => return Err(error)
        }
    }
    Ok(result)
}

fn parse_port(value: &str) -> Result<u16, String> {
    match value.parse::<u16>() {
        Ok(0) => Err("Port number cannot be zero".to_string()),
        Ok(value) => Ok(value),
        Err(_) => Err("Invalid port number".to_string())
    }
}

fn parse_host(value: &str) -> Result<IpAddr, String> {
    IpAddr::from_str(value).map_err(|_| String::from("Invalid value for an IP-address"))
}


#[cfg(test)]
mod tests {
    use super::parse_port;
    use rstest::rstest;

    mod test_parsing_uri {
        use super::super::parse_wiki_uri;

        #[test]
        fn test_invalid_uri(){
            assert_eq!(
                parse_wiki_uri("http::wrong-uri"),
                Err(String::from("Cannot parse url: http::wrong-uri"))
            );
        }

        #[test]
        fn test_invalid_protocol(){
            assert_eq!(
                parse_wiki_uri("ftp://localhost:7000/path"),
                Err(String::from("Protocol not supported: ftp"))
            );
        }

        #[test]
        fn test_correct_uri(){
            assert_eq!(
                parse_wiki_uri("http://localhost:5000/path"),
                Ok("http://localhost:5000/path".parse().unwrap())
            );
        }

        #[test]
        fn test_implied_schema_and_query(){
            assert_eq!(
                parse_wiki_uri("localhost:12345"),
                Ok("http://localhost:12345/".parse().unwrap())
            );
        }

        #[test]
        fn test_missing_authority(){
            assert_eq!(parse_wiki_uri("/path"), Err(String::from("Missing authority")));
        }

        #[test]
        fn test_illegal_query(){
            assert_eq!(
                parse_wiki_uri("http://localhost/?query"),
                Err(String::from("URL cannot contain a query"))
            );
        }
    }

    mod test_parsing_hex {
        use hex_literal::hex;
        use generic_array::typenum::U10;
        use super::super::parse_hex_string;

        #[test]
        fn test_string_too_short(){
            assert_eq!(
                parse_hex_string::<U10>(&"112233445566778899"),
                Err(String::from("String is too short, 20 hex digits expected"))
            );
        }

        #[test]
        fn test_string_too_long(){
            assert_eq!(
                parse_hex_string::<U10>(&"11223344556677889900AA"),
                Err(String::from("String is too long, 20 hex digits expected"))
            );
        }

        #[test]
        fn test_invalid_character(){
            assert_eq!(
                parse_hex_string::<U10>(&"112233~4556677889900"),
                Err(String::from("Invalid character at position 7"))
            );
        }

        #[test]
        fn test_correct_lowercase(){
            match parse_hex_string::<U10>(&"0123456789abcdef0123") {
                Ok(result) => assert_eq!(result[..], hex!("0123456789abcdef0123")),
                Err(_) => assert!(false)
            }
        }

        #[test]
        fn test_correct_uppercase(){
            match parse_hex_string::<U10>(&"0123456789ABCDEF0123") {
                Ok(result) => assert_eq!(result[..], hex!("0123456789abcdef0123")),
                Err(_) => assert!(false)
            }
        }
    }

    mod test_parsing_credentials {
        use rstest::rstest;
        use hex_literal::hex;
        use crate::credentials::{UserCredentials, CredentialsStore};
        use super::super::parse_credentials;
        use super::super::ProxyConfig;

        #[rstest(input, error,
            case ("user:password", "Wrong number of components"),
            case (
                "user:s:291e247d155354e48fec2b579637782446821935fc96a5a08a0b7885179c408b",
                "The value for salt is too short"
            ),
            case (
                "user:ABCDEF:291e247d155354e48fec2b579637782446821935fc96a5a08a0b7885",
                "Password hash is not valid (String is too short, 64 hex digits expected)"
            ),
            case (
                ":ABCDEF:291e247d155354e48fec2b579637782446821935fc96a5a08a0b7885179c408b; \
                user:FEDCBA:f64671af1dd46e4a00a48a2c7c6a3658d107507391b6eb0d9111b2b3d326512b",
                "User without a username must be the only user"
            )
        )]
        fn test_invalid_credentials(input: &str, error: &str) {
            assert_eq!(parse_credentials(input).unwrap_err(), error)
        }

        #[rstest(input, expected,
            case (
                "user:ABCDEF:291e247d155354e48fec2b579637782446821935fc96a5a08a0b7885179c408b",
                vec![
                    (Some("user".to_string()), UserCredentials::new(
                        "ABCDEF".to_string(),
                        hex!("291e247d155354e48fec2b579637782446821935fc96a5a08a0b7885179c408b"
                    )))
                ]
            ),
            case (
                ":ABCDEF:291e247d155354e48fec2b579637782446821935fc96a5a08a0b7885179c408b",
                vec![
                    (None, UserCredentials::new(
                        "ABCDEF".to_string(),
                        hex!("291e247d155354e48fec2b579637782446821935fc96a5a08a0b7885179c408b"
                    )))
                ]
            ),
            case (
                "user1:ABCDEF:291e247d155354e48fec2b579637782446821935fc96a5a08a0b7885179c408b; \
                 user2:FEDCBA:aa3a9608d21b2facdd897c37fc2e34f7c0f569c9bf6cfe4e5e413fb6310d0fc8",
                vec![
                    (Some("user1".to_string()), UserCredentials::new(
                        "ABCDEF".to_string(),
                        hex!("291e247d155354e48fec2b579637782446821935fc96a5a08a0b7885179c408b"
                    ))),
                    (Some("user2".to_string()), UserCredentials::new(
                        "FEDCBA".to_string(),
                        hex!("aa3a9608d21b2facdd897c37fc2e34f7c0f569c9bf6cfe4e5e413fb6310d0fc8"
                    ))),
                ]
            ),
        )]
        fn test_valid_credentials(input: &str, expected: Vec<(Option<String>, UserCredentials)>){
            assert_eq!(parse_credentials(input).unwrap(), expected)
        }

        #[test]
        fn test_credentials_store(){
            let config = ProxyConfig::from_values(
                "localhost",
                "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
                "user1:ABCDEF:5ebb11dc077b1ecbf1a226571fecfe15ce48924de7c12c9b478bac660dd816b8; \
                 user2:FEDCBA:61aa1f3ae8e8cfafe089ed0c0c115f316e126c27032ef171e89329cb5de67145",
                 None, None
            ).unwrap();
            assert_eq!(config.credentials_for(None), None);
            assert!(config.can_login(Some("user1"), "password"));
            assert!(config.can_login(Some("user2"), "another"));
        }
    }

    #[rstest(value, expected,
        case("8080", Ok(8080)),
        case("0", Err("Port number cannot be zero".to_string())),
        case("70000", Err("Invalid port number".to_string())),
        case("-400", Err("Invalid port number".to_string())),
        case("123ab", Err("Invalid port number".to_string()))
    )]
    fn test_parse_port_number(value: &str, expected: Result<u16, String>){
        assert_eq!(parse_port(value), expected);
    }
}
