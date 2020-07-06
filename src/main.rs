use std::sync::Arc;
use hyper::{Server};
use hyper::service::{service_fn, make_service_fn};
use hyper::server::conn::AddrStream;
use std::convert::Infallible;
use hyper::{Body, Request};
use futures::future::FutureExt;
use clap::{App, load_yaml};

mod auth;
mod proxy;
mod config;
use config::{ProxyConfig};
mod service;
mod credentials;


#[tokio::main]
async fn main() {
    let args_config = load_yaml!("../data/arguments.yml");
    let options = App::from(args_config).get_matches();

    let config = match ProxyConfig::from_args(&options) {
        Ok(uri) => uri,
        Err((option, error)) => {
            eprintln!("Invalid value for --{}: {}", option, error);
            return
        }
    };

    let config_arc = Arc::new(config);
    let config_copy = config_arc.clone();

    let listener_service = move |_socket: &AddrStream| {
        let config_arc = Arc::clone(&config_arc);
        async move {
            Ok::<_, Infallible>(service_fn(move |request: Request<Body>| {
                let config_arc = Arc::clone(&config_arc);
                service::handle(request, config_arc).map(Ok::<_, Infallible>)
            }))
        }
    };

    let server = Server::bind(&config_copy.socket_addr())
        .serve(make_service_fn(listener_service));
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
