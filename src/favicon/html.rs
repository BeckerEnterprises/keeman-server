//! Icon candidates of a page: `<link rel>` with `icon`,
//! `apple-touch-icon` or `apple-touch-icon-precomposed`, ordered by size
//! (close to 64 px, at least 32), then `/favicon.ico`.

use scraper::Html;
use url::Url;

const RELS: [&str; 3] = ["icon", "apple-touch-icon", "apple-touch-icon-precomposed"];

/// Size of an `apple-touch-icon` without `sizes`.
const APPLE_TOUCH_SIZE: u32 = 180;

struct Candidate {
    url: Url,
    size: Option<u32>,
}

/// The largest `min(width, height)` of `sizes`; `None` for `any` or nothing.
fn size_of(sizes: Option<&str>) -> Option<u32> {
    sizes?
        .split_ascii_whitespace()
        .filter_map(|token| {
            let (width, height) = token.split_once(['x', 'X'])?;
            let width: u32 = width.parse().ok()?;
            let height: u32 = height.parse().ok()?;
            Some(width.min(height))
        })
        .max()
}

/// Sort class and key: sizes from 64 up, then 32–63 down, then unknown in
/// document order, then below 32 down.
fn rank(size: Option<u32>) -> (u8, i64) {
    match size {
        Some(size) if size >= 64 => (0, i64::from(size)),
        Some(size) if size >= 32 => (1, -i64::from(size)),
        None => (2, 0),
        Some(size) => (3, -i64::from(size)),
    }
}

/// Candidates of `html` fetched from `page`, best first, ending with
/// `<origin>/favicon.ico` of `root`.
pub fn candidates(html: &str, page: &Url, root: &Url) -> Vec<Url> {
    let document = Html::parse_document(html);
    let elements: Vec<_> = document.root_element().descendent_elements().collect();
    let base = elements
        .iter()
        .find(|element| element.value().name() == "base" && element.attr("href").is_some())
        .and_then(|element| page.join(element.attr("href")?.trim()).ok())
        .filter(|url| matches!(url.scheme(), "http" | "https"))
        .unwrap_or_else(|| page.clone());
    let mut found: Vec<Candidate> = Vec::new();
    for element in &elements {
        if element.value().name() != "link" {
            continue;
        }
        let Some(rel) = element.attr("rel") else {
            continue;
        };
        let rels: Vec<String> = rel
            .split_ascii_whitespace()
            .map(str::to_ascii_lowercase)
            .collect();
        if !rels.iter().any(|token| RELS.contains(&token.as_str())) {
            continue;
        }
        if element
            .attr("type")
            .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("image/svg+xml"))
        {
            continue;
        }
        let Some(url) = element
            .attr("href")
            .and_then(|href| base.join(href.trim()).ok())
        else {
            continue;
        };
        if !matches!(url.scheme(), "http" | "https")
            || url.path().to_ascii_lowercase().ends_with(".svg")
        {
            continue;
        }
        let apple = !rels.iter().any(|token| token == "icon");
        let size = size_of(element.attr("sizes")).or(apple.then_some(APPLE_TOUCH_SIZE));
        if !found.iter().any(|known| known.url == url) {
            found.push(Candidate { url, size });
        }
    }
    found.sort_by_key(|candidate| rank(candidate.size));
    let mut urls: Vec<Url> = found.into_iter().map(|candidate| candidate.url).collect();
    with_fallback(&mut urls, root);
    urls
}

/// Appends `<origin>/favicon.ico` unless it is already a candidate.
pub fn with_fallback(urls: &mut Vec<Url>, root: &Url) {
    if let Ok(fallback) = root.join("/favicon.ico")
        && !urls.contains(&fallback)
    {
        urls.push(fallback);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(html: &str) -> Vec<String> {
        let page = Url::parse("https://www.example.com/start/").unwrap();
        let root = Url::parse("https://www.example.com/").unwrap();
        candidates(html, &page, &root)
            .into_iter()
            .map(|url| url.to_string())
            .collect()
    }

    #[test]
    fn without_links_only_the_fallback_remains() {
        assert_eq!(
            list("<html><head><title>x</title></head></html>"),
            ["https://www.example.com/favicon.ico"]
        );
        assert_eq!(list(""), ["https://www.example.com/favicon.ico"]);
    }

    #[test]
    fn orders_by_size_close_to_64() {
        let html = r#"<head>
            <link rel="icon" href="/16.png" sizes="16x16">
            <link rel="icon" href="/any.ico">
            <link rel="icon" href="/32.png" sizes="32x32">
            <link rel="icon" href="/192.png" sizes="192x192">
            <link rel="apple-touch-icon" href="/apple.png">
            <link rel="icon" href="/48.png" sizes="48x48">
            <link rel="icon" href="/64.png" sizes="64x64 16x16">
            <link rel="icon" href="/unknown.png" sizes="any">
            <link rel="icon" href="/24.png" sizes="24x24">
        </head>"#;
        assert_eq!(
            list(html),
            [
                "https://www.example.com/64.png",
                "https://www.example.com/apple.png",
                "https://www.example.com/192.png",
                "https://www.example.com/48.png",
                "https://www.example.com/32.png",
                "https://www.example.com/any.ico",
                "https://www.example.com/unknown.png",
                "https://www.example.com/24.png",
                "https://www.example.com/16.png",
                "https://www.example.com/favicon.ico",
            ]
        );
    }

    #[test]
    fn reads_rel_tokens_without_case_and_skips_others() {
        let html = r#"<head>
            <LINK REL="Shortcut Icon" HREF="a.ico">
            <link rel="apple-touch-icon-precomposed" href="b.png" sizes="57x57">
            <link rel="mask-icon" href="mask.png">
            <link rel="stylesheet" href="style.css">
            <link rel="icon">
            <link href="norel.png">
        </head>"#;
        assert_eq!(
            list(html),
            [
                "https://www.example.com/start/b.png",
                "https://www.example.com/start/a.ico",
                "https://www.example.com/favicon.ico",
            ]
        );
    }

    #[test]
    fn skips_svg_data_and_other_schemes() {
        let html = r#"<head>
            <link rel="icon" type="image/svg+xml" href="/icon">
            <link rel="icon" type=" Image/SVG+XML " href="/icon2">
            <link rel="icon" href="/icon.SVG?v=2">
            <link rel="icon" href="data:image/png;base64,iVBORw0KGgo=">
            <link rel="icon" href="ftp://example.com/icon.png">
            <link rel="icon" href="javascript:alert(1)">
            <link rel="icon" href="//cdn.example.net/icon.png">
        </head>"#;
        assert_eq!(
            list(html),
            [
                "https://cdn.example.net/icon.png",
                "https://www.example.com/favicon.ico",
            ]
        );
    }

    #[test]
    fn honours_the_first_base() {
        let html = r#"<head>
            <base href="https://static.example.org/assets/">
            <base href="https://ignored.example/">
            <link rel="icon" href="icon.png" sizes="64x64">
        </head>"#;
        assert_eq!(
            list(html),
            [
                "https://static.example.org/assets/icon.png",
                "https://www.example.com/favicon.ico",
            ]
        );
    }

    #[test]
    fn keeps_the_fallback_once_and_drops_duplicates() {
        let html = r#"<link rel="icon" href="/favicon.ico"><link rel="icon" href="/favicon.ico">"#;
        assert_eq!(list(html), ["https://www.example.com/favicon.ico"]);
    }

    #[test]
    fn sizes_use_the_smaller_side_and_the_largest_entry() {
        assert_eq!(size_of(Some("16x16 32X32 180x120")), Some(120));
        assert_eq!(size_of(Some("any")), None);
        assert_eq!(size_of(Some("x16 16 axb")), None);
        assert_eq!(size_of(None), None);
    }
}
