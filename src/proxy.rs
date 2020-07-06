use hyper::{Uri, Request, Body, Response, Client, StatusCode};
use http::uri::Builder;


fn transfer_parts(local_uri: &Uri, remote_uri: &Uri) -> Uri {
    let mut path_and_query = String::new();
    path_and_query.push_str(remote_uri.path());

    let local_path = &local_uri.path();
    if local_path != &"/" {
        if path_and_query.ends_with('/') {
            path_and_query.push_str(&local_path[1..]);
        } else {
            path_and_query.push_str(local_path);
        }
    }
    if let Some(query) = local_uri.query() {
        path_and_query.push('?');
        path_and_query.push_str(query);
    }

    Builder::new()
        .scheme(remote_uri.scheme().unwrap_or(&http::uri::Scheme::HTTP).clone())
        .authority(remote_uri.authority().unwrap().clone())
        .path_and_query(path_and_query.parse::<http::uri::PathAndQuery>().unwrap())
        .build()
        .unwrap()
}


pub async fn run_proxy(req: Request<Body>, remote_uri: &Uri, username: &str) -> Response<Body> {
    let client = Client::new();
    let mut request_builder = Request::builder()
        .uri(transfer_parts(req.uri(), remote_uri))
        .method(req.method());
    if username != "" {
        request_builder = request_builder.header("X-Auth-Username", username);
    }
    match client.request(request_builder.body(req.into_body()).unwrap()).await {
        Ok(response) => response,
        Err(_) => Response::builder().status(StatusCode::BAD_GATEWAY).body(Body::empty()).unwrap()
    }
}


#[cfg(test)]
mod tests {
    use rstest::rstest;
    use http::{Uri, Request};
    use httpmock::{Mock, MockServer};
    use super::{run_proxy, transfer_parts};
    use hyper::{Body};
    use futures::stream::StreamExt;


    #[rstest(from, to, expected,
        case("http://localhost:5000/", "http://localhost:7000/", "http://localhost:7000/"),
        case("http://localhost:5000/abc", "http://localhost:7000/", "http://localhost:7000/abc"),
        case("http://localhost:5000/abc/def", "http://localhost:7000/", "http://localhost:7000/abc/def"),
        case("http://localhost:5000/abc/", "http://localhost:7000/", "http://localhost:7000/abc/"),
        case("http://localhost:5000/abc/def/", "http://localhost:7000/", "http://localhost:7000/abc/def/"),
        case("http://localhost:5000/abc?a=1", "http://localhost:7000/", "http://localhost:7000/abc?a=1"),
        case("http://localhost:5000/abc?a=1&b=2", "http://localhost:7000/", "http://localhost:7000/abc?a=1&b=2"),

        case("http://localhost:5000/", "http://localhost:7000/x", "http://localhost:7000/x"),
        case("http://localhost:5000/abc", "http://localhost:7000/x", "http://localhost:7000/x/abc"),
        case("http://localhost:5000/abc", "http://localhost:7000/x/", "http://localhost:7000/x/abc"),
        case("http://localhost:5000/abc/def", "http://localhost:7000/x", "http://localhost:7000/x/abc/def"),
        case("http://localhost:5000/abc?a=1", "http://localhost:7000/x", "http://localhost:7000/x/abc?a=1"),
        case("http://localhost:5000/abc?a=1&b=2", "http://localhost:7000/x", "http://localhost:7000/x/abc?a=1&b=2"),
    )]
    fn test_transfer_parts(from: &str, to: &str, expected: &str){
        let actual = transfer_parts(&from.parse::<Uri>().unwrap(), &to.parse::<Uri>().unwrap());
        assert_eq!(actual, expected.parse::<Uri>().unwrap());
    }

    #[tokio::test]
    async fn test_get_proxy(){
        let mock_server = MockServer::start();
        let url: Uri = format!("http://{}/", mock_server.address()).parse().unwrap();

        let mock = Mock::new()
            .expect_method(httpmock::Method::GET)
            .expect_path("/hello")
            .expect_query_param("q", "123")
            .expect_header("X-Auth-Username", "user")
            .return_status(200)
            .return_header("X-Return-Header", "Return-Header")
            .return_body("Hello, world")
            .create_on(&mock_server);

        let request = Request::builder()
            .uri("/hello?q=123".parse::<Uri>().unwrap())
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let response = run_proxy(request, &url, "user").await;
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers().get("X-Return-Header").unwrap(), "Return-Header");
        let body = String::from_utf8(response.into_body()
            .map(|c| c.unwrap().to_vec())
            .concat().await).unwrap();
        assert_eq!(body, "Hello, world");
        assert_eq!(mock.times_called(), 1);
    }

    #[tokio::test]
    async fn test_post_proxy(){
        let mock_server = MockServer::start();
        let url: Uri = format!("http://{}/", mock_server.address()).parse().unwrap();

        let mock = Mock::new()
            .expect_method(httpmock::Method::POST)
            .expect_path("/hello")
            .expect_body("Body")
            .return_status(200)
            .return_body("Hello, world")
            .create_on(&mock_server);

        let request = Request::builder()
            .uri("/hello?q=123".parse::<Uri>().unwrap())
            .method("POST")
            .body(Body::from("Body"))
            .unwrap();

        let response = run_proxy(request, &url, "").await;
        assert_eq!(response.status(), 200);
        let body = String::from_utf8(response.into_body()
            .map(|c| c.unwrap().to_vec())
            .concat().await).unwrap();
        assert_eq!(body, "Hello, world");
        assert_eq!(mock.times_called(), 1);
    }

    #[tokio::test]
    async fn test_no_remote(){
        let url: Uri = format!("http://127.0.0.1:45792/").parse().unwrap();
        let request = Request::builder()
            .uri("/path".parse::<Uri>().unwrap())
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let response = run_proxy(request, &url, "").await;
        assert_eq!(response.status(), 502);
    }

}
