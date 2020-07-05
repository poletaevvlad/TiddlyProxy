use std::sync::Arc;
use hyper::{Server};
use hyper::service::{service_fn, make_service_fn};
use std::net::SocketAddr;
use hyper::server::conn::AddrStream;
use std::convert::Infallible;
use hyper::{Body, Request};
use futures::future::FutureExt;

mod auth;
mod proxy;
mod config;
use config::{parse_options, ProxyConfig};
mod service;


#[tokio::main]
async fn main() {
    let options = parse_options();
    let config = match ProxyConfig::from_args(&options) {
        Ok(uri) => uri,
        Err((option, error)) => {
            eprintln!("Invalid value for --{}: {}", option, error);
            return
        }
    };
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    let config_arc = Arc::new(config);

    let listener_service = move |_socket: &AddrStream| {
        let config_arc = Arc::clone(&config_arc);
        async move {
            Ok::<_, Infallible>(service_fn(move |request: Request<Body>| {
                let config_arc = Arc::clone(&config_arc);
                service::handle(request, config_arc).map(Ok::<_, Infallible>)
            }))
        }
    };

    let server = Server::bind(&addr).serve(make_service_fn(listener_service));
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
