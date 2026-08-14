//! The HTTP stack kdt talks to the API server through: kube-rs' own, with DNS results put back
//! in order.
//!
//! kdt ships as a static musl binary, and musl's `getaddrinfo` does not implement the address
//! sorting of RFC 6724 — it hands back whatever the resolver returned, in that order. On a network
//! that does DNS64, an IPv4-only API server also answers with a synthesised `64:ff9b::/96` AAAA,
//! and that address comes out first. hyper's happy eyeballs does not save us there: it races the
//! *TCP* connects, and a NAT64 gateway that has no route completes the handshake in milliseconds
//! and then swallows everything, so IPv6 "wins" the race and the TLS handshake hangs until the
//! connect timeout. glibc clients (kubectl, k9s) never see this because their resolver sorts IPv4
//! first. So we sort it ourselves.
//!
//! Only the resolver changes. Everything else mirrors what `ClientBuilder::try_from(Config)` does,
//! and a kubeconfig with a `proxy-url` is left to kube entirely: there the proxy resolves the name,
//! never us. Two things kube's own stack adds are dropped because they are out of reach or unused:
//! the tracing layer, and the `valid_until` expiry it reads from an `exec` credential — kdt never
//! consults it, and the accessor is crate-private.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Result;
use hyper_timeout::TimeoutConnector;
use hyper_util::client::legacy::connect::dns::{GaiResolver, Name};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use kube::client::{Body, ConfigExt};
use kube::{Client, Config};
use tower::{Service, ServiceBuilder};

/// Build the client for a kubeconfig context.
pub fn build(config: Config) -> Result<Client> {
    // With a proxy, the name is resolved at the far end — the local resolver is out of the picture,
    // and rebuilding kube's socks5/http tunnel here would only be a chance to get it wrong.
    if config.proxy_url.is_some() {
        return Ok(Client::try_from(config)?);
    }

    let mut http = HttpConnector::new_with_resolver(Ipv4First::new());
    // The URL carries an https scheme; without this the connector refuses it outright.
    http.enforce_http(false);
    let https = config.rustls_https_connector_with_connector(http)?;

    let mut connector = TimeoutConnector::new(https);
    connector.set_connect_timeout(config.connect_timeout);
    connector.set_read_timeout(config.read_timeout);
    connector.set_write_timeout(config.write_timeout);

    let hyper = hyper_util::client::legacy::Builder::new(TokioExecutor::new()).build::<_, Body>(connector);

    let default_ns = config.default_namespace.clone();
    let service = ServiceBuilder::new()
        .layer(config.base_uri_layer())
        .option_layer(config.auth_layer()?)
        .layer(config.extra_headers_layer()?)
        // The auth layer only accepts an inner service whose error is already boxed.
        .map_err(tower::BoxError::from)
        .service(hyper);

    Ok(Client::new(service, default_ns))
}

/// `GaiResolver` with the answers reordered: IPv4 first, everything else after it, each family
/// keeping the order the resolver gave.
#[derive(Clone)]
struct Ipv4First(GaiResolver);

impl Ipv4First {
    fn new() -> Self {
        Self(GaiResolver::new())
    }
}

impl Service<Name> for Ipv4First {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let fut = self.0.call(name);
        Box::pin(async move { Ok(ipv4_first(fut.await?.collect()).into_iter()) })
    }
}

// A stable sort, so an API server that publishes several A records is still tried in the order its
// DNS returned them. IPv6-only clusters are untouched: with no IPv4 in the list there is nothing
// to move ahead of anything.
fn ipv4_first(mut addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    addrs.sort_by_key(|a| !a.is_ipv4());
    addrs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_nat64_answer_no_longer_comes_first() {
        // What musl hands back on a DNS64 network for an IPv4-only API server.
        let got = ipv4_first(vec![addr("[64:ff9b::338a:2d7b]:443"), addr("51.138.45.123:443")]);
        assert_eq!(got, vec![addr("51.138.45.123:443"), addr("[64:ff9b::338a:2d7b]:443")]);
    }

    #[test]
    fn each_family_keeps_the_order_dns_gave() {
        let got = ipv4_first(vec![
            addr("[2001:db8::2]:443"),
            addr("10.0.0.2:443"),
            addr("[2001:db8::1]:443"),
            addr("10.0.0.1:443"),
        ]);
        assert_eq!(
            got,
            vec![
                addr("10.0.0.2:443"),
                addr("10.0.0.1:443"),
                addr("[2001:db8::2]:443"),
                addr("[2001:db8::1]:443"),
            ]
        );
    }

    #[test]
    fn an_ipv6_only_cluster_is_left_alone() {
        let v6 = vec![addr("[2001:db8::1]:443"), addr("[2001:db8::2]:443")];
        assert_eq!(ipv4_first(v6.clone()), v6);
    }
}
