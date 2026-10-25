//! One GET of the favicon proxy: redirects by hand,
//! each target checked again, and a byte limit while streaming.

use reqwest::header::{ACCEPT, CONTENT_TYPE, LOCATION};
use reqwest::{Client, StatusCode};
use url::Url;

use super::policy::Policy;
use super::target;

pub const MAX_REDIRECTS: usize = 3;

pub struct Fetched {
    /// The URL after redirects; relative links resolve against it.
    pub url: Url,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

/// What to do with a body over the limit.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Overflow {
    /// Keep the first bytes (HTML: the links are in the head).
    Truncate,
    /// Give up (images).
    Fail,
}

/// Why a fetch failed; never carries the URL, so it cannot end up in a log.
#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    NotAllowed,
    Request,
    Status,
    TooManyRedirects,
    TooLarge,
}

pub async fn get(
    client: &Client,
    policy: &dyn Policy,
    mut url: Url,
    accept: &'static str,
    limit: usize,
    overflow: Overflow,
) -> Result<Fetched, Failure> {
    let mut redirects = 0;
    loop {
        if !target::allowed(&url, policy) {
            return Err(Failure::NotAllowed);
        }
        let mut response = client
            .get(url.clone())
            .header(ACCEPT, accept)
            .send()
            .await
            .map_err(|_| Failure::Request)?;
        let status = response.status();
        if matches!(
            status,
            StatusCode::MOVED_PERMANENTLY
                | StatusCode::FOUND
                | StatusCode::SEE_OTHER
                | StatusCode::TEMPORARY_REDIRECT
                | StatusCode::PERMANENT_REDIRECT
        ) {
            redirects += 1;
            if redirects > MAX_REDIRECTS {
                return Err(Failure::TooManyRedirects);
            }
            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or(Failure::Status)?;
            url = url.join(location).map_err(|_| Failure::NotAllowed)?;
            continue;
        }
        if !status.is_success() {
            return Err(Failure::Status);
        }
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Failure::Request)? {
            if body.len() + chunk.len() > limit {
                if overflow == Overflow::Fail {
                    return Err(Failure::TooLarge);
                }
                body.extend_from_slice(&chunk[..limit - body.len()]);
                break;
            }
            body.extend_from_slice(&chunk);
        }
        return Ok(Fetched {
            url,
            content_type,
            body,
        });
    }
}
