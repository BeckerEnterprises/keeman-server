//! SSRF-protected favicon proxy: fetches the page of an origin,
//! picks icon candidates and returns the first decodable one as a 64 × 64
//! PNG. Neither URL nor host is ever logged; failures carry no URL.

pub mod fetch;
pub mod html;
pub mod image;
pub mod policy;
pub mod resolve;
pub mod target;

use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use rustls::crypto::ring;
use rustls_platform_verifier::BuilderVerifierExt;
use url::Url;

use self::fetch::Overflow;
use self::policy::{Blocklist, Policy};
use self::resolve::{CheckedResolver, Lookup, SystemLookup};

const USER_AGENT: &str = "KeeMan-Favicon/1.0 (+https://www.keeman.org)";
const HTML_ACCEPT: &str = "text/html,application/xhtml+xml";
const IMAGE_ACCEPT: &str = "image/*";
const HTML_LIMIT: usize = 512 * 1024;
const IMAGE_LIMIT: usize = 256 * 1024;
/// Image fetches per request.
pub const MAX_IMAGES: usize = 4;

#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    pub connect: Duration,
    /// Page, redirects and images together.
    pub total: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(3),
            total: Duration::from_secs(8),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum FaviconError {
    /// `400 url_not_allowed`: a reason in the URL itself.
    NotAllowed,
    /// `422 favicon_not_found`: everything after DNS resolution.
    NotFound,
}

pub struct Favicon {
    pub png: Vec<u8>,
    /// Origin of the requested URL.
    pub origin: String,
}

pub struct Favicons {
    client: Client,
    policy: Arc<dyn Policy>,
    total: Duration,
}

impl Favicons {
    /// The production proxy: system DNS and the fixed blocklist.
    pub fn new() -> Result<Self, String> {
        Self::with(
            Arc::new(SystemLookup::new()?),
            Arc::new(Blocklist),
            Timeouts::default(),
        )
    }

    /// A proxy with another resolver, policy and timeouts (tests).
    pub fn with(
        lookup: Arc<dyn Lookup>,
        policy: Arc<dyn Policy>,
        timeouts: Timeouts,
    ) -> Result<Self, String> {
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("cannot configure TLS: {e}"))?
            .with_platform_verifier()
            .map_err(|e| format!("cannot load the system certificates: {e}"))?
            .with_no_client_auth();
        let client = Client::builder()
            .tls_backend_preconfigured(tls)
            .dns_resolver(Arc::new(CheckedResolver {
                lookup,
                policy: policy.clone(),
            }))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .http1_only()
            .pool_max_idle_per_host(0)
            .connect_timeout(timeouts.connect)
            .user_agent(USER_AGENT)
            .build()
            .map_err(|e| format!("cannot create the favicon client: {e}"))?;
        Ok(Self {
            client,
            policy,
            total: timeouts.total,
        })
    }

    pub async fn fetch(&self, url: &str) -> Result<Favicon, FaviconError> {
        let (page, origin) = target::input(url, &*self.policy).ok_or(FaviconError::NotAllowed)?;
        let png = tokio::time::timeout(self.total, self.find(page))
            .await
            .ok()
            .flatten()
            .ok_or(FaviconError::NotFound)?;
        Ok(Favicon { png, origin })
    }

    async fn find(&self, root: Url) -> Option<Vec<u8>> {
        let page = fetch::get(
            &self.client,
            &*self.policy,
            root.clone(),
            HTML_ACCEPT,
            HTML_LIMIT,
            Overflow::Truncate,
        )
        .await;
        let candidates = match page {
            Ok(page) if is_html(page.content_type.as_deref()) => {
                html::candidates(&String::from_utf8_lossy(&page.body), &page.url, &root)
            }
            _ => {
                let mut urls = Vec::new();
                html::with_fallback(&mut urls, &root);
                urls
            }
        };
        for url in candidates.into_iter().take(MAX_IMAGES) {
            let Ok(image) = fetch::get(
                &self.client,
                &*self.policy,
                url,
                IMAGE_ACCEPT,
                IMAGE_LIMIT,
                Overflow::Fail,
            )
            .await
            else {
                continue;
            };
            if let Some(png) = image::icon(&image.body) {
                return Some(png);
            }
        }
        None
    }
}

fn is_html(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|value| value.split(';').next())
        .map(|kind| kind.trim().to_ascii_lowercase())
        .is_some_and(|kind| kind == "text/html" || kind == "application/xhtml+xml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_html_pages_count() {
        assert!(is_html(Some("text/html")));
        assert!(is_html(Some("Text/HTML; charset=utf-8")));
        assert!(is_html(Some("application/xhtml+xml")));
        assert!(!is_html(Some("image/png")));
        assert!(!is_html(Some("text/plain")));
        assert!(!is_html(None));
    }
}
