use std::sync::Arc;
use hyper::{Request, Response, Body};

use crate::config::ProxyConfig;
use crate::proxy::run_proxy;


pub async fn handle(request: Request<Body>, config: Arc<ProxyConfig>) -> Response<Body> {
    run_proxy(request, config.remote_uri()).await
}
