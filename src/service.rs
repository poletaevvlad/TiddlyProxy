use std::sync::Arc;
use hyper::{Request, Response, Body};
use hyper::header::HeaderValue;
use cookie::Cookie;
use crate::config::ProxyConfig;
use crate::proxy::run_proxy;
use crate::auth::{AuthConfig, Token};
use std::time::SystemTime;

fn is_authenitcated<'a, B, T: AuthConfig<'a>>(request: Request<B>, config: &'a T) -> bool{
    match request.headers().get("Cookie").map(HeaderValue::to_str) {
        Some(Ok(cookies)) => {
            let auth_cookie = cookies.split(";")
                .map(Cookie::parse)
                .filter(Result::is_ok)
                .map(Result::unwrap)
                .filter(|c| c.name() == "proxy_auth")
                .map(|c| String::from(c.value()))
                .next();

            match auth_cookie {
                Some(token) => {
                    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
                    Token::verify(&token, config, now).is_ok()
                }
                None => false
            }
        }
        _ => false
    }
}


pub async fn handle(request: Request<Body>, config: Arc<ProxyConfig>) -> Response<Body> {
    run_proxy(request, config.remote_uri()).await
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;
    use hyper::Request;
    use super::is_authenitcated;
    use crate::auth::Token;
    use crate::auth::tests::MockConfig;

    #[test]
    fn test_auth_no_cookies() {
        let request = Request::builder().body(()).unwrap();
        let config = MockConfig::new(*b"00112233445566778899AABBCCDDEEFF");
        assert!(!is_authenitcated(request, &config));
    }

    #[test]
    fn test_auth_no_invalid_cookie_syntax() {
        let request = Request::builder()
            .header("Cookie", "invalid-value")
            .body(())
            .unwrap();

        let config = MockConfig::new(*b"00112233445566778899AABBCCDDEEFF");
        assert!(!is_authenitcated(request, &config));
    }

    #[test]
    fn test_auth_no_such_cookie() {
        let request = Request::builder()
            .header("Cookie", "cookie1=2; cookie2=3")
            .body(())
            .unwrap();

        let config = MockConfig::new(*b"00112233445566778899AABBCCDDEEFF");
        assert!(!is_authenitcated(request, &config));
    }

    #[test]
    fn test_auth_wrong_cookie_value() {
        let request = Request::builder()
            .header("Cookie", "cookie1=2; proxy_auth=invalid_value; cookie2=3")
            .body(())
            .unwrap();

        let config = MockConfig::new(*b"00112233445566778899AABBCCDDEEFF");
        assert!(!is_authenitcated(request, &config));
    }

    #[test]
    fn test_auth_expired_token() {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        let config = MockConfig::new(*b"00112233445566778899AABBCCDDEEFF");

        let request = Request::builder()
            .header("Cookie", format!(
                "cookie1=2; proxy_auth={}; cookie2=3",
                Token::new(now - 100).generate(&config)
            ))
            .body(())
            .unwrap();
        assert!(!is_authenitcated(request, &config));
    }

    #[test]
    fn test_auth_valid_token() {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        let config = MockConfig::new(*b"00112233445566778899AABBCCDDEEFF");

        let request = Request::builder()
            .header("Cookie", format!(
                "cookie1=2; proxy_auth={}; cookie2=3",
                Token::new(now + 100).generate(&config)
            ))
            .body(())
            .unwrap();
        assert!(is_authenitcated(request, &config));
    }
}
