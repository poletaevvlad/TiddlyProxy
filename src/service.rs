use std::sync::Arc;
use serde::{Serialize};
use hyper::{Request, Response, Body, StatusCode};
use hyper::header::HeaderValue;
use cookie::Cookie;
use crate::config::ProxyConfig;
use crate::proxy::run_proxy;
use crate::auth::{AuthConfig, Token};
use std::time::SystemTime;
use std::ops::Deref;
use time::OffsetDateTime;
use tinytemplate::TinyTemplate;


fn is_authenitcated<'a, B, T: AuthConfig<'a>>(request: &Request<B>, config: &'a T) -> bool{
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
    let authenticated = is_authenitcated(&request, config.deref());
    if authenticated {
        let path = request.uri().path();
        if path == "/logout" || path == "/logout/" {
            let clear_cookie = Cookie::build("proxy_auth", "")
                .path("/")
                .http_only(true)
                .expires(OffsetDateTime::unix_epoch())
                .finish();

            Response::builder()
                .status(StatusCode::TEMPORARY_REDIRECT)
                .header("Location", "/")
                .header("Set-Cookie", &clear_cookie.to_string())
                .body(Body::empty())
                .unwrap()
        } else {
            run_proxy(request, config.remote_uri()).await
        }
    } else {
        if request.uri().path() == "/" {
            run_login_page(request, config)
        } else {
            Response::builder()
                .status(StatusCode::TEMPORARY_REDIRECT)
                .header("Location", "/")
                .body(Body::empty())
                .unwrap()
        }
    }
}


#[derive(Serialize)]
struct LoginFormContext {

}


fn run_login_page(_request: Request<Body>, _config: Arc<ProxyConfig>) -> Response<Body> {
    let mut template = TinyTemplate::new();
    template.add_template("login", include_str!("../data/login.html")).unwrap();

    let context = LoginFormContext{
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html")
        .body(Body::from(template.render("login", &context).unwrap()))
        .unwrap()
}


#[cfg(test)]
mod tests {
    mod test_is_authenticated {
        use std::time::SystemTime;
        use hyper::Request;
        use super::super::is_authenitcated;
        use crate::auth::Token;
        use crate::auth::tests::MockConfig;

        #[test]
        fn test_auth_no_cookies() {
            let request = Request::builder().body(()).unwrap();
            let config = MockConfig::new(*b"00112233445566778899AABBCCDDEEFF");
            assert!(!is_authenitcated(&request, &config));
        }

        #[test]
        fn test_auth_no_invalid_cookie_syntax() {
            let request = Request::builder()
                .header("Cookie", "invalid-value")
                .body(())
                .unwrap();

            let config = MockConfig::new(*b"00112233445566778899AABBCCDDEEFF");
            assert!(!is_authenitcated(&request, &config));
        }

        #[test]
        fn test_auth_no_such_cookie() {
            let request = Request::builder()
                .header("Cookie", "cookie1=2; cookie2=3")
                .body(())
                .unwrap();

            let config = MockConfig::new(*b"00112233445566778899AABBCCDDEEFF");
            assert!(!is_authenitcated(&request, &config));
        }

        #[test]
        fn test_auth_wrong_cookie_value() {
            let request = Request::builder()
                .header("Cookie", "cookie1=2; proxy_auth=invalid_value; cookie2=3")
                .body(())
                .unwrap();

            let config = MockConfig::new(*b"00112233445566778899AABBCCDDEEFF");
            assert!(!is_authenitcated(&request, &config));
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
            assert!(!is_authenitcated(&request, &config));
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
            assert!(is_authenitcated(&request, &config));
        }
    }

    mod test_navigation {
        use std::sync::Arc;
        use http::Uri;
        use httpmock::{Mock, MockServer};
        use hyper::{Request, Body};
        use crate::config::ProxyConfig;
        use crate::auth::Token;
        use super::super::handle;
        use std::time::SystemTime;
        use futures::stream::StreamExt;

        #[tokio::test]
        async fn test_redirecting_unauthenticated_to_login_page(){
            let mock_server = MockServer::start();
            let config = ProxyConfig::from_values(
                &format!("{}", mock_server.address()),
                "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
                "user:abcdef:291e247d155354e48fec2b579637782446821935fc96a5a08a0b7885179c408b"
            ).unwrap();

            let mock = Mock::new()
                .expect_method(httpmock::Method::GET)
                .expect_path("/hello")
                .create_on(&mock_server);

            let request = Request::builder()
                .uri("/hello".parse::<Uri>().unwrap())
                .method("GET")
                .body(Body::empty()).unwrap();

            let resp = handle(request, Arc::new(config)).await;
            assert_eq!(resp.status(), 307);
            assert_eq!(resp.headers().get("Location").unwrap(), "/");
            assert_eq!(mock.times_called(), 0);
        }

        #[tokio::test]
        async fn test_running_proxy_when_authenticated(){
            let mock_server = MockServer::start();
            let config = ProxyConfig::from_values(
                &format!("{}", mock_server.address()),
                "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
                "user:abcdef:291e247d155354e48fec2b579637782446821935fc96a5a08a0b7885179c408b"
            ).unwrap();

            let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
            let token = Token::new(now + 100).generate(&config);

            let mock = Mock::new()
                .expect_method(httpmock::Method::GET)
                .expect_path("/hello")
                .return_body("remote content")
                .create_on(&mock_server);

            let request = Request::builder()
                .uri("/hello".parse::<Uri>().unwrap())
                .method("GET")
                .header("Cookie", format!("proxy_auth={}", token))
                .body(Body::empty()).unwrap();

            let resp = handle(request, Arc::new(config)).await;
            assert_eq!(resp.status(), 200);
            let body = String::from_utf8(resp.into_body()
                .map(|c| c.unwrap().to_vec())
                .concat().await).unwrap();
            assert_eq!(body, "remote content");
            assert_eq!(mock.times_called(), 1);
        }

        #[tokio::test]
        async fn test_logging_out(){
            let config = ProxyConfig::from_values(
                "localhost",
                "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
                "user:abcdef:291e247d155354e48fec2b579637782446821935fc96a5a08a0b7885179c408b"
            ).unwrap();
            let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
            let token = Token::new(now + 100).generate(&config);

            let request = Request::builder()
                .uri("/logout".parse::<Uri>().unwrap())
                .method("GET")
                .header("Cookie", format!("proxy_auth={}", token))
                .body(Body::empty()).unwrap();

            let resp = handle(request, Arc::new(config)).await;
            assert_eq!(resp.status(), 307);
            assert_eq!(resp.headers().get("Location").unwrap(), "/");
            assert_eq!(
                resp.headers().get("Set-Cookie").unwrap(),
                "proxy_auth=; HttpOnly; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
            );
        }
    }
}
