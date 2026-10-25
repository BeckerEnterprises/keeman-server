//! Idempotent requests: the key is looked up first in the write
//! transaction, and the answer is stored in the same transaction, so a
//! repetition (also a concurrent one, which waits for `BEGIN IMMEDIATE`)
//! returns exactly the first answer.

use axum::Json;
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use sqlx::{Sqlite, Transaction};

use crate::crypto::sha256;
use crate::db::{self, Conn};
use crate::error::{ApiError, ApiResult, ErrorCode, StoredProblem};
use crate::extract::{json_bytes, parse_json};
use crate::types::is_canonical_uuid;

pub const HEADER: &str = "idempotency-key";

/// What identifies a request besides its key.
pub struct Idempotent {
    pub key: String,
    /// Method and concrete path, e.g. `POST /v1/vaults`.
    pub endpoint: String,
    pub hash: [u8; 32],
}

/// Reads an idempotent JSON request: `415` → `413` → `Idempotency-Key` →
/// structure.
pub async fn read<T: DeserializeOwned>(
    request: Request,
    limit: usize,
) -> ApiResult<(Idempotent, T)> {
    let endpoint = format!("{} {}", request.method(), request.uri().path());
    let mut values = request.headers().get_all(HEADER).iter();
    let key = match (values.next(), values.next()) {
        (Some(value), None) => value
            .to_str()
            .ok()
            .filter(|v| is_canonical_uuid(v))
            .map(str::to_string),
        _ => None,
    };
    let bytes = json_bytes(request, limit).await?;
    let key = key.ok_or_else(|| {
        ApiError::parameter("Idempotency-Key", "missing or invalid idempotency key")
    })?;
    let bytes = bytes.ok_or_else(|| ApiError::pointer("", "request body required"))?;
    let body = parse_json(&bytes)?;
    Ok((
        Idempotent {
            key,
            endpoint,
            hash: sha256(&bytes),
        },
        body,
    ))
}

/// The stored answer of a repetition, `422` for a reused key, or `None`
/// for a new request. Must be the first statement of the transaction.
pub async fn lookup(
    conn: &mut Conn,
    user_id: &str,
    request: &Idempotent,
) -> ApiResult<Option<Response>> {
    let Some(stored) = db::idempotency::find(conn, user_id, &request.key).await? else {
        return Ok(None);
    };
    if stored.endpoint != request.endpoint || stored.request_hash != request.hash {
        return Err(ApiError::new(ErrorCode::IdempotencyKeyReused));
    }
    let status = u16::try_from(stored.status)
        .ok()
        .and_then(|s| StatusCode::from_u16(s).ok())
        .ok_or_else(|| ApiError::internal("stored status out of range"))?;
    if status == StatusCode::NO_CONTENT {
        return Ok(Some(status.into_response()));
    }
    if status.is_success() {
        let mut response = (status, stored.response).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        return Ok(Some(response));
    }
    let body: Map<String, Value> =
        serde_json::from_slice(&stored.response).map_err(ApiError::internal)?;
    let mut response = status.into_response();
    response.extensions_mut().insert(StoredProblem(body));
    Ok(Some(response))
}

/// Whether an error from inside the transaction is a final answer that is
/// stored; server errors are not.
pub fn storable(error: &ApiError) -> bool {
    !error.code().status().is_server_error()
}

/// Ends the savepoint around the work of a request: kept on success, rolled
/// back for a stored error; server errors abort the whole transaction.
pub async fn settle<T>(
    savepoint: Transaction<'_, Sqlite>,
    result: Result<T, ApiError>,
) -> ApiResult<Result<T, ApiError>> {
    match result {
        Ok(value) => {
            savepoint.commit().await?;
            Ok(Ok(value))
        }
        Err(error) if storable(&error) => {
            savepoint.rollback().await?;
            Ok(Err(error))
        }
        Err(error) => Err(error),
    }
}

/// Stores the answer and turns it into the response of this request. A
/// `204` is stored and answered without a body.
pub async fn store(
    conn: &mut Conn,
    user_id: &str,
    request: &Idempotent,
    now: &str,
    answer: Result<(StatusCode, Value), ApiError>,
) -> ApiResult<Response> {
    let (status, bytes) = match &answer {
        Ok((StatusCode::NO_CONTENT, _)) => (StatusCode::NO_CONTENT, Vec::new()),
        Ok((status, body)) => (*status, body.to_string().into_bytes()),
        Err(error) => {
            let status = error.code().status();
            let body = Value::Object(error.problem().body(status));
            (status, body.to_string().into_bytes())
        }
    };
    let entry = db::idempotency::NewEntry {
        user_id,
        key: &request.key,
        endpoint: &request.endpoint,
        request_hash: &request.hash,
        status: i64::from(status.as_u16()),
        response: &bytes,
        now,
    };
    db::idempotency::insert(conn, &entry).await?;
    Ok(match answer {
        Ok((StatusCode::NO_CONTENT, _)) => StatusCode::NO_CONTENT.into_response(),
        Ok((status, body)) => (status, Json(body)).into_response(),
        Err(error) => error.into_response(),
    })
}
