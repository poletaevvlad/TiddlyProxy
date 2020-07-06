use std::sync::Arc;
use hyper::{Server};
use hyper::service::{service_fn, make_service_fn};
use hyper::server::conn::AddrStream;
use std::convert::Infallible;
use hyper::{Body, Request};
use futures::future::FutureExt;
use clap::{App, load_yaml, ArgMatches, crate_authors, crate_version};
use rand::prelude::*;
use rand::distributions::{Alphanumeric};
use rand_chacha::ChaCha20Rng;

mod auth;
mod proxy;
mod config;
use config::{ProxyConfig};
mod service;
mod credentials;


async fn run_reverse_proxy<'a>(matches: &'a ArgMatches<'a>) {
    let config = match ProxyConfig::from_args(matches) {
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

fn generate_secret(){
    let mut secret = [0u8; 32];
    let mut rng = ChaCha20Rng::from_entropy();
    rng.fill(&mut secret);

    for byte in secret.iter() {
        print!("{:02X}", byte);
    }
    println!("");
}

fn create_user_credential<'a>(matches: &'a ArgMatches<'a>) {
    let username = match matches.value_of("username").map(config::parse_username) {
        None => String::new(),
        Some(Ok(username)) => username,
        Some(Err(error)) => {
            eprintln!("Invalid value for --user: {}", error);
            return
        }
    };

    let password = match rpassword::prompt_password_stderr("Password: ") {
        Ok(password) => password,
        Err(_) => {
            eprintln!("Cannot read password");
            return
        }
    };

    let rng = ChaCha20Rng::from_entropy();
    let salt: String = rng.sample_iter(Alphanumeric).take(7).collect();

    let mut hash = String::with_capacity(64);
    for byte in credentials::generate_hash(&salt, &password) {
        hash.push_str(&format!("{:02X}", byte));
    }

    println!("{}:{}:{}", username, salt, hash);

}

#[tokio::main]
async fn main() {
    let args_config = load_yaml!("../data/arguments.yml");
    let options = App::from(args_config)
        .version(crate_version!())
        .author(crate_authors!())
        .get_matches();

    match options.subcommand() {
        ("run", Some(matches)) => run_reverse_proxy(matches).await,
        ("gensecret", _) => generate_secret(),
        ("mkuser", Some(matches)) => create_user_credential(matches),
        _ => {}
    }
}
