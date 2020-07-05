use http::uri::Uri;
use clap::{App, Arg, ArgMatches};
use generic_array::{GenericArray, ArrayLength};
use generic_array::typenum::U32;
use crate::auth::AuthConfig;


pub fn parse_options<'a>() -> ArgMatches<'a>{
    App::new("TiddlyWiki Authentication Proxy")
        .arg(Arg::with_name("wiki_url")
            .help("URL of a running TiddlyWiki node.js server")
            .long("wiki_url")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("secret")
            .help("Randomly generated 32-byte hexadecimal string")
            .long("secret")
            .takes_value(true)
            .required(true))
        .get_matches()
}


#[derive(Debug)]
pub struct ProxyConfig {
    remote_uri: Uri,
    secret: GenericArray<u8, U32>
}

impl ProxyConfig {
    pub fn from_values(wiki_url: &str, secret: &str) -> Result<ProxyConfig, (&'static str, String)> {
        let remote_uri = match parse_wiki_uri(wiki_url) {
            Ok(uri) => uri,
            Err(error) => return Err(("wiki_url", error))
        };

        let secret = match parse_hex_string::<U32>(secret) {
            Ok(buffer) => buffer,
            Err(error) => return Err(("secret", error))
        };

        Ok(ProxyConfig{
            remote_uri: remote_uri,
            secret: secret
        })
    }

    pub fn from_args<'a>(matches: &ArgMatches<'a>) -> Result<ProxyConfig, (&'static str, String)> {
        ProxyConfig::from_values(
            matches.value_of("wiki_url").unwrap(),
            matches.value_of("secret").unwrap()
        )
    }

    pub fn remote_uri(&self) -> &Uri {
        &self.remote_uri
    }
}

impl<'a> AuthConfig<'a> for ProxyConfig {
    fn secret(&'a self) -> &'a [u8;32] {
        self.secret.as_ref()
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


#[cfg(test)]
mod tests {
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
}
