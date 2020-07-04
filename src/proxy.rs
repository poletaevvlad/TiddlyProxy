use hyper::Uri;
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


#[cfg(test)]
mod tests {
    use rstest::rstest;
    use hyper::Uri;
    use super::transfer_parts;

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

}
