//! Accounts as other accounts see them: lookup by e-mail address and the
//! public key of a co-member. Clients compute fingerprints from the
//! key themselves.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Request, State};
use serde::Deserialize;
use serde_json::{Value, json};

use super::vaults::path_uuid;
use crate::app::App;
use crate::auth::{AuthSession, NoQuery};
use crate::db;
use crate::error::{ApiError, ApiResult, ErrorCode};
use crate::extract::json;
use crate::ratelimit::{Bucket, Quota};
use crate::types::{Email, encode_base64url};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookupBody {
    email: Email,
}

fn public(user: db::users::PublicUser) -> Value {
    json!({
        "user_id": user.id,
        "email": user.email,
        "public_key": encode_base64url(&user.public_key),
    })
}

/// Rate limit → `415` → `413` → structure → `404 user_not_found`.
pub async fn lookup(
    State(app): State<Arc<App>>,
    session: AuthSession,
    _: NoQuery,
    request: Request,
) -> ApiResult<Json<Value>> {
    app.limit(
        Bucket::Lookup,
        &session.user_id,
        Quota::per_hour(app.config.rate_limits.lookup_per_account_per_hour),
    )?;
    let body: LookupBody = json(request).await?;
    let user = db::users::public_by_email(&app.db.read, &body.email.0)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::UserNotFound))?;
    Ok(Json(public(user)))
}

/// Only for the own account and accounts that share a membership, pending
/// ones included; otherwise `404 user_not_found`.
pub async fn public_key(
    State(app): State<Arc<App>>,
    session: AuthSession,
    _: NoQuery,
    Path(path): Path<String>,
) -> ApiResult<Json<Value>> {
    let user_id = path_uuid("user_id", &path)?;
    let not_found = || ApiError::new(ErrorCode::UserNotFound);
    if user_id != session.user_id
        && !db::vaults::shares_membership(&app.db.read, &session.user_id, user_id).await?
    {
        return Err(not_found());
    }
    let user = db::users::public_by_id(&app.db.read, user_id)
        .await?
        .ok_or_else(not_found)?;
    Ok(Json(public(user)))
}
