use http::uri::Uri;
use clap::{App, Arg, ArgMatches};


pub fn parse_options<'a>() -> ArgMatches<'a>{
    App::new("TiddlyWiki Authentication Proxy")
        .arg(Arg::with_name("wiki_url")
            .help("URL of a running TiddlyWiki node.js server")
            .long("wiki_url")
            .takes_value(true)
            .required(true))
        .get_matches()
}


#[derive(Debug)]
pub struct ProxyConfig {
    remote_uri: Uri
}

impl ProxyConfig {
    pub fn from_args<'a>(matches: &ArgMatches<'a>) -> Result<ProxyConfig, (&'static str, String)>{
        let remote_uri = match parse_wiki_uri(matches.value_of("wiki_url").unwrap()) {
            Ok(uri) => uri,
            Err(error) => return Err(("wiki_url", error))
        };

        Ok(ProxyConfig {
            remote_uri: remote_uri
        })
    }

    pub fn remote_uri(&self) -> &Uri {
        &self.remote_uri
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



#[cfg(test)]
mod tests {
    use super::parse_wiki_uri;

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
