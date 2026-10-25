//! DNS for the favicon proxy: every resolved address must be
//! allowed, and the HTTP client connects to exactly the first one. Check and
//! connection use the same lookup, so DNS rebinding cannot slip in between.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::LookupIpStrategy;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use super::policy::Policy;

pub type LookupResult = Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>>;

/// Name resolution; production uses [`SystemLookup`], tests a fixed table
/// (the port of an address replaces the default port of the scheme).
pub trait Lookup: Send + Sync + 'static {
    fn lookup(&self, host: String) -> Pin<Box<dyn Future<Output = LookupResult> + Send>>;
}

/// The system's resolver configuration through hickory, IPv4 first.
pub struct SystemLookup(TokioResolver);

impl SystemLookup {
    pub fn new() -> Result<Self, String> {
        let mut builder = TokioResolver::builder_tokio()
            .map_err(|e| format!("cannot read the DNS configuration: {e}"))?;
        builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4thenIpv6;
        let resolver = builder
            .build()
            .map_err(|e| format!("cannot create the DNS resolver: {e}"))?;
        Ok(Self(resolver))
    }
}

impl Lookup for SystemLookup {
    fn lookup(&self, host: String) -> Pin<Box<dyn Future<Output = LookupResult> + Send>> {
        let resolver = self.0.clone();
        Box::pin(async move {
            let ips = resolver.lookup_ip(host).await?;
            Ok(ips.iter().map(|ip| SocketAddr::new(ip, 0)).collect())
        })
    }
}

#[derive(Debug)]
struct Refused;

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("address not allowed")
    }
}

impl std::error::Error for Refused {}

/// The resolver of the favicon client.
pub struct CheckedResolver {
    pub lookup: Arc<dyn Lookup>,
    pub policy: Arc<dyn Policy>,
}

impl Resolve for CheckedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let lookup = self.lookup.clone();
        let policy = self.policy.clone();
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addrs = lookup.lookup(host).await?;
            let first = *addrs.first().ok_or(Refused)?;
            if addrs.iter().any(|addr| !policy.allows(addr.ip())) {
                return Err(Refused.into());
            }
            Ok(Box::new(std::iter::once(first)) as Addrs)
        })
    }
}
