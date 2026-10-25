//! The favicon proxy: `404 feature_disabled` → rate limit → `415`
//! → `413` → structure → `400 url_not_allowed` → fetch (`422`). Neither the
//! URL nor its host is logged.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Request, State};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::app::App;
use crate::auth::{AuthSession, NoQuery};
use crate::error::{ApiError, ApiResult, ErrorCode};
use crate::extract::json;
use crate::favicon::FaviconError;
use crate::favicon::image::SIZE;
use crate::ratelimit::{Bucket, Quota};
use crate::types::{FaviconUrl, encode_base64url};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaviconBody {
    url: FaviconUrl,
}

pub async fn fetch(
    State(app): State<Arc<App>>,
    session: AuthSession,
    _: NoQuery,
    request: Request,
) -> ApiResult<Json<Value>> {
    let Some(favicons) = app.favicon.as_ref().filter(|_| app.config.features.favicon) else {
        return Err(ApiError::new(ErrorCode::FeatureDisabled));
    };
    app.limit(
        Bucket::Favicon,
        &session.user_id,
        Quota::per_minute(app.config.rate_limits.favicon_per_account_per_min),
    )?;
    let body: FaviconBody = json(request).await?;
    let favicon = favicons.fetch(&body.url.0).await.map_err(|error| {
        ApiError::new(match error {
            FaviconError::NotAllowed => ErrorCode::UrlNotAllowed,
            FaviconError::NotFound => ErrorCode::FaviconNotFound,
        })
    })?;
    Ok(Json(json!({
        "mime": "image/png",
        "data": encode_base64url(&favicon.png),
        "width": SIZE,
        "height": SIZE,
        "origin": favicon.origin,
    })))
}
