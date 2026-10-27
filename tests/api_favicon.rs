//! `POST /v1/favicon` and the SSRF test suite.
//! A local site on 127.0.0.1 stands in for the internet, names come from a
//! table, and an "internal" listener on 127.0.0.2 must never be reached.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use image::codecs::ico::{IcoEncoder, IcoFrame};
use image::codecs::png::PngEncoder;
use image::{ExtendedColorType, ImageEncoder, Rgba, RgbaImage};
use keeman_server::favicon::policy::{Policy, is_blocked};
use keeman_server::favicon::resolve::{Lookup, LookupResult};
use keeman_server::favicon::{Favicons, Timeouts};
use serde_json::{Value, json};
use support::{Req, TestApp, TestResponse, config_in};
use tokio::net::TcpListener;

const RED: [u8; 4] = [255, 0, 0, 255];
const GREEN: [u8; 4] = [0, 255, 0, 255];
const BLUE: [u8; 4] = [0, 0, 255, 255];

#[derive(Clone)]
enum Reply {
    Html(String),
    Body(&'static str, Vec<u8>),
    Redirect(u16, String),
    Status(u16),
    Slow(Duration, Box<Reply>),
}

#[derive(Default)]
struct SiteState {
    routes: Mutex<HashMap<String, Reply>>,
    hits: Mutex<Vec<String>>,
}

async fn serve(State(site): State<Arc<SiteState>>, request: Request) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_string();
    let path = request
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();
    let key = format!("{host}{path}");
    site.hits.lock().unwrap().push(key.clone());
    let reply = site.routes.lock().unwrap().get(&key).cloned();
    match reply {
        Some(reply) => render(reply).await,
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn render(reply: Reply) -> Pin<Box<dyn Future<Output = Response> + Send>> {
    Box::pin(async move {
        match reply {
            Reply::Html(html) => {
                ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response()
            }
            Reply::Body(kind, bytes) => {
                ([(header::CONTENT_TYPE, kind)], Body::from(bytes)).into_response()
            }
            Reply::Redirect(status, location) => (
                StatusCode::from_u16(status).unwrap(),
                [(header::LOCATION, location)],
            )
                .into_response(),
            Reply::Status(status) => StatusCode::from_u16(status).unwrap().into_response(),
            Reply::Slow(delay, reply) => {
                tokio::time::sleep(delay).await;
                render(*reply).await
            }
        }
    })
}

/// Names and their answers; each lookup takes the next answer and repeats
/// the last one.
#[derive(Default)]
struct Table {
    answers: Mutex<HashMap<String, VecDeque<Vec<SocketAddr>>>>,
    calls: Mutex<Vec<String>>,
}

impl Table {
    fn set(&self, host: &str, answers: Vec<Vec<SocketAddr>>) {
        self.answers
            .lock()
            .unwrap()
            .insert(host.to_string(), answers.into());
    }

    fn calls(&self, host: &str) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|h| *h == host)
            .count()
    }

    fn total(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

impl Lookup for Table {
    fn lookup(&self, host: String) -> Pin<Box<dyn Future<Output = LookupResult> + Send>> {
        self.calls.lock().unwrap().push(host.clone());
        let answer = {
            let mut answers = self.answers.lock().unwrap();
            match answers.get_mut(&host) {
                Some(queue) if queue.len() > 1 => queue.pop_front(),
                Some(queue) => queue.front().cloned(),
                None => None,
            }
        };
        Box::pin(async move { answer.ok_or_else(|| "unknown name".into()) })
    }
}

/// The blocklist, except the local test site on exactly 127.0.0.1. Tests
/// never name 127.0.0.1 itself: on port 80 it would reach the host's web
/// server.
struct TestPolicy;

impl Policy for TestPolicy {
    fn allows(&self, ip: IpAddr) -> bool {
        ip == IpAddr::V4(Ipv4Addr::LOCALHOST) || !is_blocked(ip)
    }
}

struct World {
    t: TestApp,
    site: Arc<SiteState>,
    table: Arc<Table>,
    internal: Arc<AtomicUsize>,
    token: String,
}

impl World {
    async fn new() -> Self {
        Self::with(Timeouts::default(), "").await
    }

    async fn with(timeouts: Timeouts, extra: &str) -> Self {
        let site = Arc::new(SiteState::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let site_addr = listener.local_addr().unwrap();
        let app = Router::new().fallback(serve).with_state(site.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let internal = Arc::new(AtomicUsize::new(0));
        let inner = TcpListener::bind("127.0.0.2:0").await.unwrap();
        let internal_addr = inner.local_addr().unwrap();
        let count = internal.clone();
        tokio::spawn(async move {
            while let Ok((_stream, _)) = inner.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
            }
        });

        let table = Arc::new(Table::default());
        for host in ["site.test", "other.test"] {
            table.set(host, vec![vec![site_addr]]);
        }
        table.set("internal.test", vec![vec![internal_addr]]);
        table.set("mixed.test", vec![vec![site_addr, internal_addr]]);
        table.set("rebind.test", vec![vec![site_addr], vec![internal_addr]]);

        let favicons = Favicons::with(table.clone(), Arc::new(TestPolicy), timeouts).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(dir.path(), extra);
        let t = TestApp::with_favicons(config, dir, Some(favicons)).await;
        let token = t.register("alice@example.com").await.access_token;
        Self {
            t,
            site,
            table,
            internal,
            token,
        }
    }

    fn route(&self, key: &str, reply: Reply) {
        self.site
            .routes
            .lock()
            .unwrap()
            .insert(key.to_string(), reply);
    }

    fn reset(&self) {
        self.site.routes.lock().unwrap().clear();
        self.site.hits.lock().unwrap().clear();
    }

    fn hits(&self) -> Vec<String> {
        self.site.hits.lock().unwrap().clone()
    }

    async fn fetch(&self, url: &str) -> TestResponse {
        self.t
            .call(
                Req::post("/v1/favicon")
                    .token(&self.token)
                    .json(&json!({ "url": url })),
            )
            .await
    }

    fn internal_connections(&self) -> usize {
        self.internal.load(Ordering::SeqCst)
    }
}

fn png(width: u32, height: u32, color: [u8; 4]) -> Vec<u8> {
    let image = RgbaImage::from_pixel(width, height, Rgba(color));
    let mut out = Vec::new();
    PngEncoder::new(&mut out)
        .write_image(image.as_raw(), width, height, ExtendedColorType::Rgba8)
        .unwrap();
    out
}

fn ico(color: [u8; 4]) -> Vec<u8> {
    let image = RgbaImage::from_pixel(32, 32, Rgba(color));
    let mut out = Vec::new();
    IcoEncoder::new(&mut out)
        .encode_images(&[
            IcoFrame::as_png(image.as_raw(), 32, 32, ExtendedColorType::Rgba8).unwrap(),
        ])
        .unwrap();
    out
}

fn image_reply(color: [u8; 4]) -> Reply {
    Reply::Body("image/png", png(32, 32, color))
}

/// The centre pixel of an answer's icon, which must be a 64 × 64 PNG.
fn centre(response: &TestResponse) -> [u8; 4] {
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    let body = response.json();
    let bytes = keeman_server::types::decode_base64url(body["data"].as_str().unwrap()).unwrap();
    let image = image::load_from_memory_with_format(&bytes, image::ImageFormat::Png)
        .unwrap()
        .to_rgba8();
    assert_eq!(image.dimensions(), (64, 64));
    image.get_pixel(32, 32).0
}

fn assert_not_found(response: &TestResponse) {
    assert_eq!(
        response.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        response.text()
    );
    assert_eq!(response.code(), "favicon_not_found");
}

#[tokio::test]
async fn picks_the_candidate_closest_to_64_pixels() {
    let w = World::new().await;
    w.route(
        "site.test/",
        Reply::Html(
            r#"<!doctype html><html><head>
            <link rel="icon" href="/16.png" sizes="16x16">
            <link rel="apple-touch-icon" href="/apple.png">
            <link rel="icon" href="/64.png" sizes="64x64">
            </head><body>Hello</body></html>"#
                .into(),
        ),
    );
    w.route(
        "site.test/16.png",
        Reply::Body("image/png", png(16, 16, RED)),
    );
    w.route(
        "site.test/apple.png",
        Reply::Body("image/png", png(180, 180, GREEN)),
    );
    w.route(
        "site.test/64.png",
        Reply::Body("image/png", png(64, 64, BLUE)),
    );

    let response = w.fetch("http://site.test/login/form?next=%2Fx#top").await;
    assert_eq!(centre(&response), BLUE);
    let body = response.json();
    assert_eq!(body["mime"], json!("image/png"));
    assert_eq!(body["width"], json!(64));
    assert_eq!(body["height"], json!(64));
    assert_eq!(body["origin"], json!("http://site.test"));
    assert_eq!(body.as_object().unwrap().len(), 5);
    // Only the origin's page and the chosen image were fetched.
    assert_eq!(w.hits(), ["site.test/", "site.test/64.png"]);
}

#[tokio::test]
async fn falls_back_to_favicon_ico_without_a_usable_page() {
    let w = World::new().await;
    for page in [
        Some(Reply::Html(
            "<html><head><title>No icons</title></head></html>".into(),
        )),
        Some(Reply::Body("image/png", png(8, 8, RED))),
        Some(Reply::Status(500)),
        None,
    ] {
        w.reset();
        if let Some(page) = page {
            w.route("site.test/", page);
        }
        w.route(
            "site.test/favicon.ico",
            Reply::Body("image/x-icon", ico(GREEN)),
        );
        assert_eq!(centre(&w.fetch("http://site.test").await), GREEN);
        assert_eq!(w.hits(), ["site.test/", "site.test/favicon.ico"]);
    }
}

#[tokio::test]
async fn skips_unusable_candidates_and_fetches_at_most_four_images() {
    let w = World::new().await;
    let svg = br#"<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64"/>"#.to_vec();
    let links = ["a", "b", "c", "d", "e"]
        .map(|name| format!(r#"<link rel="icon" sizes="64x64" href="/{name}.png">"#))
        .join("");
    let routes = |w: &World| {
        w.route("site.test/", Reply::Html(format!("<head>{links}</head>")));
        w.route("site.test/a.png", Reply::Body("image/png", svg.clone()));
        w.route(
            "site.test/b.png",
            Reply::Body("image/png", vec![7u8; 300 * 1024]),
        );
        w.route(
            "site.test/c.png",
            Reply::Body("image/png", png(1025, 1, RED)),
        );
        w.route(
            "site.test/favicon.ico",
            Reply::Body("image/x-icon", ico(RED)),
        );
    };
    // d is missing, e would be fine: four failed image fetches end the search.
    routes(&w);
    w.route("site.test/e.png", image_reply(GREEN));
    assert_not_found(&w.fetch("http://site.test/").await);
    assert_eq!(
        w.hits(),
        [
            "site.test/",
            "site.test/a.png",
            "site.test/b.png",
            "site.test/c.png",
            "site.test/d.png",
        ]
    );

    w.reset();
    routes(&w);
    w.route("site.test/d.png", image_reply(BLUE));
    assert_eq!(centre(&w.fetch("http://site.test/").await), BLUE);
}

#[tokio::test]
async fn follows_at_most_three_redirects() {
    let w = World::new().await;
    w.route("site.test/", Reply::Redirect(301, "/r1".into()));
    w.route("site.test/r1", Reply::Redirect(302, "r2".into()));
    w.route(
        "site.test/r2",
        Reply::Redirect(307, "http://other.test/r3/".into()),
    );
    w.route(
        "other.test/r3/",
        Reply::Html(r#"<link rel="icon" href="icon.png">"#.into()),
    );
    w.route(
        "other.test/r3/icon.png",
        Reply::Redirect(308, "/real.png".into()),
    );
    w.route("other.test/real.png", image_reply(BLUE));
    let response = w.fetch("http://site.test/").await;
    assert_eq!(centre(&response), BLUE);
    // The origin of the request, not of the redirect target.
    assert_eq!(response.json()["origin"], json!("http://site.test"));

    // A fourth redirect ends the page fetch; the fallback belongs to the
    // requested origin.
    w.reset();
    w.route("site.test/", Reply::Redirect(301, "/r1".into()));
    w.route("site.test/r1", Reply::Redirect(302, "/r2".into()));
    w.route("site.test/r2", Reply::Redirect(303, "/r3".into()));
    w.route("site.test/r3", Reply::Redirect(307, "/page".into()));
    w.route(
        "site.test/page",
        Reply::Html(r#"<link rel="icon" href="/icon.png">"#.into()),
    );
    w.route("site.test/icon.png", image_reply(RED));
    w.route(
        "site.test/favicon.ico",
        Reply::Body("image/x-icon", ico(GREEN)),
    );
    assert_eq!(centre(&w.fetch("http://site.test/").await), GREEN);
    assert!(!w.hits().contains(&"site.test/page".to_string()));
}

#[tokio::test]
async fn redirects_and_links_to_forbidden_targets_are_refused() {
    let w = World::new().await;
    for target in [
        "http://127.0.0.2/",
        "http://127.2/",
        "http://0x7f000002/",
        "http://10.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.2]/",
        "http://internal.test/x",
        "http://mixed.test/x",
        "http://unknown.test/x",
        "ftp://site.test/x",
        "file:///etc/passwd",
        "http://site.test:8080/x",
        "http://user:pw@site.test/x",
    ] {
        w.reset();
        w.route("site.test/favicon.ico", Reply::Redirect(302, target.into()));
        assert_not_found(&w.fetch("http://site.test/").await);

        w.reset();
        w.route(
            "site.test/",
            Reply::Html(format!(r#"<link rel="icon" href="{target}">"#)),
        );
        assert_not_found(&w.fetch("http://site.test/").await);
    }
    assert_eq!(w.internal_connections(), 0);
}

#[tokio::test]
async fn names_with_blocked_addresses_are_refused_without_connecting() {
    let w = World::new().await;
    for url in [
        "http://internal.test/",
        "http://mixed.test/",
        "http://unknown.test/",
    ] {
        assert_not_found(&w.fetch(url).await);
    }
    assert_eq!(w.internal_connections(), 0);
    assert!(w.hits().is_empty());
    assert!(w.table.calls("internal.test") > 0);
}

#[tokio::test]
async fn dns_rebinding_never_reaches_the_internal_address() {
    let w = World::new().await;
    // The first lookup is public, every later one internal.
    w.route(
        "rebind.test/",
        Reply::Html(r#"<link rel="icon" href="/icon.png">"#.into()),
    );
    w.route("rebind.test/icon.png", image_reply(BLUE));
    assert_not_found(&w.fetch("http://rebind.test/").await);
    assert_eq!(w.hits(), ["rebind.test/"]);
    // Every connection resolved anew and was refused at the second lookup.
    assert!(w.table.calls("rebind.test") >= 2);
    assert_eq!(w.internal_connections(), 0);
}

#[tokio::test]
async fn reasons_in_the_url_give_400_before_any_lookup() {
    let w = World::new().await;
    for url in [
        "",
        "site.test",
        "/favicon.ico",
        "ftp://site.test/",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "https://user@site.test/",
        "https://user:pw@site.test/",
        "https://site.test:8443/",
        "http://site.test:22/",
        "http://127.0.0.2/",
        "http://127.2/",
        "http://0x7f.0.0.2/",
        "http://0177.0.0.2/",
        "http://2130706434/",
        "http://0/",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://169.254.169.254/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.2]/",
        "http://[64:ff9b::a00:1]/",
        "http://[2002:7f00:1::]/",
        "http://[fe80::1]/",
        "http://[fd00::1]/",
    ] {
        let response = w.fetch(url).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{url}");
        assert_eq!(response.code(), "url_not_allowed", "{url}");
    }
    assert_eq!(w.table.total(), 0);
    assert!(w.hits().is_empty());
}

#[tokio::test]
async fn large_pages_are_cut_after_512_kib() {
    let w = World::new().await;
    let padding = "<!-- padding -->".repeat(600 * 1024 / 16);
    w.route(
        "site.test/",
        Reply::Html(format!(
            r#"<head><link rel="icon" sizes="16x16" href="/early.png">{padding}<link rel="icon" sizes="64x64" href="/late.png"></head>"#
        )),
    );
    w.route("site.test/early.png", image_reply(GREEN));
    w.route("site.test/late.png", image_reply(RED));
    assert_eq!(centre(&w.fetch("http://site.test/").await), GREEN);
}

#[tokio::test]
async fn slow_sites_time_out() {
    let timeouts = Timeouts {
        connect: Duration::from_millis(500),
        total: Duration::from_secs(1),
    };
    let w = World::with(timeouts, "").await;
    w.route(
        "site.test/",
        Reply::Slow(
            Duration::from_secs(5),
            Box::new(Reply::Html(r#"<link rel="icon" href="/icon.png">"#.into())),
        ),
    );
    w.route("site.test/icon.png", image_reply(BLUE));
    let started = Instant::now();
    assert_not_found(&w.fetch("http://site.test/").await);
    assert!(started.elapsed() < Duration::from_secs(4));

    // A slow image counts against the same total.
    w.reset();
    w.route(
        "site.test/",
        Reply::Html(r#"<link rel="icon" href="/icon.png">"#.into()),
    );
    w.route(
        "site.test/icon.png",
        Reply::Slow(Duration::from_secs(5), Box::new(image_reply(BLUE))),
    );
    let started = Instant::now();
    assert_not_found(&w.fetch("http://site.test/").await);
    assert!(started.elapsed() < Duration::from_secs(4));
}

#[tokio::test]
async fn feature_disabled_comes_before_everything_else() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_in(
        dir.path(),
        "[features]\nfavicon = false\n[rate_limits]\nfavicon_per_account_per_min = 1\n",
    );
    let t = TestApp::with_favicons(config, dir, None).await;
    let alice = t.register("alice@example.com").await;
    for request in [
        Req::post("/v1/favicon")
            .token(&alice.access_token)
            .json(&json!({ "url": "https://example.com" })),
        Req::post("/v1/favicon")
            .token(&alice.access_token)
            .raw(Some("text/plain"), b"x"),
        Req::post("/v1/favicon").token(&alice.access_token),
    ] {
        let response = t.call(request).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);
        assert_eq!(response.code(), "feature_disabled");
    }
    let config = t.call(Req::get("/v1/config")).await.json();
    assert_eq!(
        config["features"],
        json!({ "favicon": false, "manifest": true })
    );
}

#[tokio::test]
async fn the_rate_limit_is_per_account_and_separate_from_the_session_limit() {
    let w = World::with(
        Timeouts::default(),
        "[rate_limits]\nfavicon_per_account_per_min = 2\nsession_per_min = 1\n",
    )
    .await;
    for _ in 0..2 {
        assert_eq!(w.fetch("ftp://site.test/").await.code(), "url_not_allowed");
    }
    let limited = w.fetch("ftp://site.test/").await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.header("retry-after").is_some());
    // The favicon requests did not use the session's single request.
    let me = w.t.call(Req::get("/v1/me").token(&w.token)).await;
    assert_eq!(me.status, StatusCode::OK, "{}", me.text());
    // Another account has its own bucket.
    let bob = w.t.register("bob@example.com").await;
    let other =
        w.t.call(
            Req::post("/v1/favicon")
                .token(&bob.access_token)
                .json(&json!({ "url": "ftp://site.test/" })),
        )
        .await;
    assert_eq!(other.code(), "url_not_allowed");
}

#[tokio::test]
async fn bodies_are_checked_before_the_proxy() {
    let w = World::new().await;
    let call = |request: Req| w.t.call(request.token(&w.token));
    let response = call(Req::post("/v1/favicon").raw(Some("text/plain"), b"{}")).await;
    assert_eq!(response.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let too_long = format!("http://site.test/{}", "a".repeat(2049 - 17));
    assert_eq!(too_long.chars().count(), 2049);
    let response = call(Req::post("/v1/favicon").json(&json!({ "url": too_long }))).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.code(), "validation_failed");
    assert_eq!(response.json()["errors"][0]["pointer"], json!("/url"));
    assert!(!response.text().contains("aaaa"));

    for body in [
        json!({}),
        json!({ "url": 5 }),
        json!({ "url": "https://example.com", "size": 64 }),
    ] {
        let response = call(Req::post("/v1/favicon").json(&body)).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(response.code(), "validation_failed");
    }

    let longest = format!("ftp://site.test/{}", "a".repeat(2048 - 16));
    assert_eq!(longest.chars().count(), 2048);
    let response = call(Req::post("/v1/favicon").json(&json!({ "url": longest }))).await;
    assert_eq!(response.code(), "url_not_allowed");
    assert!(w.hits().is_empty());
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn logs_hold_no_urls_or_hosts() {
    use keeman_server::config::LogLevel;
    use tracing_subscriber::layer::SubscriberExt;

    let captured = Captured::default();
    let writer = captured.clone();
    // The same filter as the server, with everything at its most verbose.
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish()
        .with(keeman_server::logging::targets(LogLevel::Trace));
    let _guard = tracing::subscriber::set_default(subscriber);

    let w = World::new().await;
    w.route(
        "site.test/",
        Reply::Html(r#"<link rel="icon" href="/secret-icon-path.png">"#.into()),
    );
    w.route("site.test/secret-icon-path.png", image_reply(BLUE));
    assert_eq!(
        centre(&w.fetch("http://site.test/secret-page?token=abc").await),
        BLUE
    );
    assert_not_found(&w.fetch("http://internal.test/").await);
    assert_not_found(&w.fetch("http://other.test/").await);
    assert_eq!(w.fetch("http://10.9.8.7/").await.code(), "url_not_allowed");
    // DNS crates name queried hosts even on warn, so they stay silent.
    tracing::warn!(target: "hickory_net::udp::udp_client_stream", "ignoring response for site.test");
    tracing::error!(target: "hickory_resolver::name_server_pool", "rejecting site.test");

    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("\"path\":\"/v1/favicon\""), "{logs}");
    for value in [
        "site.test",
        "internal.test",
        "other.test",
        "secret-page",
        "secret-icon-path",
        "token=abc",
        "10.9.8.7",
        "127.0.0.1:",
        "127.0.0.2",
    ] {
        assert!(!logs.contains(value), "logs contain {value}: {logs}");
    }
}

#[tokio::test]
async fn answers_are_problem_json_without_the_url() {
    let w = World::new().await;
    let response = w.fetch("http://internal.test/secret").await;
    assert_not_found(&response);
    let body: Value = response.json();
    assert!(!body.to_string().contains("internal.test"));
    let response = w.fetch("http://user:secret@site.test/").await;
    assert_eq!(response.code(), "url_not_allowed");
    assert!(!response.text().contains("secret"));
}
