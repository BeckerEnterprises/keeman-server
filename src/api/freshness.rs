//! Freshness attestations: each account stores its latest one per vault and
//! one for its user data. The server checks the canonical bytes, that the
//! caller made it, and the signature against the caller's registered
//! signing key; what the attestation says only the account's clients judge.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Deserialize;

use super::vaults::{Need, require, vault_id};
use crate::app::App;
use crate::auth::{AuthSession, NoQuery};
use crate::clock::format_timestamp;
use crate::db::{self, Conn};
use crate::error::{ApiError, ApiResult, ErrorCode};
use crate::extract::StrictJson;
use crate::freshness::{self, Statement};
use crate::types::{FreshnessBytes, Signature};

/// An attestation as it travels through the API.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedFreshness {
    statement: FreshnessBytes,
    signature: Signature,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreshnessBody {
    freshness: SignedFreshness,
}

fn invalid(detail: &'static str) -> ApiError {
    ApiError::pointer("/freshness", detail)
}

/// Which attestation an endpoint takes.
enum Subject<'a> {
    Vault(&'a str),
    UserData,
}

/// Canonical and valid, about this subject, made by the caller (`400`);
/// the caller has a signing key (`409 signing_key_missing`) and the
/// signature verifies with it (`400`).
async fn check(
    conn: &mut Conn,
    user_id: &str,
    signed: &SignedFreshness,
    subject: Subject<'_>,
) -> ApiResult<()> {
    let bytes = &signed.statement.0;
    let statement =
        freshness::parse(bytes).ok_or_else(|| invalid("invalid freshness statement"))?;
    let fits = match (&statement, subject) {
        (Statement::Vault { vault_id, .. }, Subject::Vault(path)) => vault_id == path,
        (Statement::UserData { .. }, Subject::UserData) => true,
        _ => false,
    };
    if !fits {
        return Err(invalid("the statement is about something else"));
    }
    if statement.user_id() != user_id {
        return Err(invalid("the caller must make the statement"));
    }
    let key = match db::users::signing_key(&mut *conn, user_id).await? {
        Some(Some(key)) => key,
        Some(None) => return Err(ApiError::new(ErrorCode::SigningKeyMissing)),
        None => return Err(ApiError::new(ErrorCode::SessionInvalid)),
    };
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| ApiError::internal("stored signing key has a wrong length"))?;
    if !freshness::verify(&key, bytes, &signed.signature.0) {
        return Err(invalid("the signature does not verify"));
    }
    Ok(())
}

/// `PUT /v1/vaults/{id}/freshness`: active members only.
pub async fn put_vault(
    State(app): State<Arc<App>>,
    session: AuthSession,
    _: NoQuery,
    Path(path): Path<String>,
    StrictJson(body): StrictJson<FreshnessBody>,
) -> ApiResult<StatusCode> {
    let vault_id = vault_id(&path)?;
    let user_id = session.user_id.as_str();
    let now = format_timestamp(app.now());
    let mut tx = app.db.begin().await?;
    require(&mut tx, vault_id, user_id, Need::Member).await?;
    check(&mut tx, user_id, &body.freshness, Subject::Vault(vault_id)).await?;
    let row = db::freshness::NewAttestation {
        user_id,
        statement: &body.freshness.statement.0,
        signature: &body.freshness.signature.0,
        now: &now,
    };
    db::freshness::put_vault(&mut tx, vault_id, &row).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /v1/me/freshness`: the attestation for the user data.
pub async fn put_user_data(
    State(app): State<Arc<App>>,
    session: AuthSession,
    _: NoQuery,
    StrictJson(body): StrictJson<FreshnessBody>,
) -> ApiResult<StatusCode> {
    let user_id = session.user_id.as_str();
    let now = format_timestamp(app.now());
    let mut tx = app.db.begin().await?;
    check(&mut tx, user_id, &body.freshness, Subject::UserData).await?;
    let row = db::freshness::NewAttestation {
        user_id,
        statement: &body.freshness.statement.0,
        signature: &body.freshness.signature.0,
        now: &now,
    };
    db::freshness::put_user(&mut tx, &row).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
