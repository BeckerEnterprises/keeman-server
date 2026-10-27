//! The roles chain of a vault: reading it, appending a statement without a
//! key change, and the check every new statement passes in the writing
//! transaction, against the stored head and the active owners afterwards.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{StatusCode, Uri};
use serde::Deserialize;
use serde_json::{Value, json};

use super::objects::counter;
use super::vaults::{Need, require, vault_id};
use crate::app::App;
use crate::audit::Audit;
use crate::auth::{AuthSession, ClientIp, NoQuery};
use crate::clock::format_timestamp;
use crate::db::{self, Conn};
use crate::error::{ApiError, ApiResult, ErrorCode};
use crate::events;
use crate::extract::{StrictJson, parse_query};
use crate::roles;
use crate::types::{Signature, StatementBytes, encode_base64url};

/// A statement as it travels through the API.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRoles {
    statement: StatementBytes,
    signature: Signature,
}

/// The vault as it is after the operation the statement belongs to.
pub struct After {
    /// Active owners afterwards with their registered keys.
    pub owners: Vec<db::roles::AccountKeys>,
    /// Key version of the vault afterwards.
    pub key_version: i64,
    /// A rotation: the statement commits to a new key.
    pub new_key: bool,
}

/// A statement that passed the check, ready to become the head.
pub struct Checked {
    version: i64,
    bytes: Vec<u8>,
    signature: [u8; 64],
    hash: [u8; 32],
    signer: String,
}

fn invalid(detail: &'static str) -> ApiError {
    ApiError::pointer("/roles", detail)
}

/// Whether the registered keys of every owner afterwards include a signing
/// key; an owner without one cannot appear in a statement.
pub fn require_signing_keys(owners: &[db::roles::AccountKeys]) -> ApiResult<()> {
    if owners.iter().any(|o| o.signing_public_key.is_none()) {
        return Err(ApiError::new(ErrorCode::SigningKeyMissing));
    }
    Ok(())
}

/// Checks a statement: canonical and valid (`400`), following the stored
/// head (`409 roles_conflict`), signed by the caller as an owner of the head
/// (`400`), naming exactly the owners afterwards with their registered keys
/// (`400`), with the key version afterwards and, without a key change, the
/// head's key commitment (`400`). Every answer is final.
pub async fn check(
    conn: &mut Conn,
    vault_id: &str,
    caller: &str,
    signed: &SignedRoles,
    after: &After,
) -> ApiResult<Checked> {
    require_signing_keys(&after.owners)?;
    let bytes = &signed.statement.0;
    let statement = roles::parse(bytes).ok_or_else(|| invalid("invalid roles statement"))?;
    let head = db::roles::head(conn, vault_id).await?;
    let head_version = head.as_ref().map_or(0, |h| h.version);
    let head_statement = match &head {
        Some(head) => Some(
            roles::parse(&head.statement)
                .ok_or_else(|| ApiError::internal("stored roles statement is unreadable"))?,
        ),
        None => None,
    };
    let follows = statement.vault_id == vault_id
        && statement.version == head_version + 1
        && match &head {
            Some(head) => statement
                .previous
                .is_some_and(|previous| previous[..] == head.hash[..]),
            None => statement.previous.is_none(),
        };
    if !follows {
        return Err(ApiError::roles_conflict(head_version));
    }
    if statement.signer != caller {
        return Err(invalid("the caller must sign the statement"));
    }
    let signer = match &head_statement {
        Some(head) => head.owner(caller),
        None => statement.owner(caller),
    }
    .ok_or_else(|| invalid("the signer is not an owner"))?;
    if !roles::verify(&signer.signing_key, bytes, &signed.signature.0) {
        return Err(invalid("the signature does not verify"));
    }
    let mut owners: Vec<&db::roles::AccountKeys> = after.owners.iter().collect();
    owners.sort_by(|a, b| a.user_id.cmp(&b.user_id));
    let same_owners = owners.len() == statement.owners.len()
        && owners
            .iter()
            .zip(&statement.owners)
            .all(|(registered, named)| {
                registered.user_id == named.user_id
                    && registered.public_key == named.public_key
                    && registered.signing_public_key.as_deref() == Some(&named.signing_key[..])
            });
    if !same_owners {
        return Err(invalid("the owners do not match the vault"));
    }
    let key_fits = statement.key_version == after.key_version
        && match &head_statement {
            None => !after.new_key,
            Some(head) if after.new_key => statement.key_version == head.key_version + 1,
            Some(head) => {
                statement.key_version == head.key_version
                    && statement.key_commitment == head.key_commitment
            }
        };
    if !key_fits {
        return Err(invalid("the key version does not match"));
    }
    Ok(Checked {
        version: statement.version,
        hash: roles::hash(bytes),
        bytes: bytes.clone(),
        signature: signed.signature.0,
        signer: statement.signer,
    })
}

/// Stores a checked statement as the new head, with its security-log entry.
pub async fn store(
    conn: &mut Conn,
    audit: &Audit,
    vault_id: &str,
    checked: &Checked,
    now: &str,
    ip_hint: &str,
) -> ApiResult<()> {
    let row = db::roles::NewStatement {
        vault_id,
        version: checked.version,
        statement: &checked.bytes,
        signature: &checked.signature,
        hash: &checked.hash,
        now,
    };
    db::roles::insert(conn, &row).await?;
    audit
        .vault_log(
            conn,
            now,
            "roles_changed",
            &checked.signer,
            vault_id,
            Some(ip_hint),
            json!({ "version": checked.version, "signer": checked.signer }),
        )
        .await?;
    Ok(())
}

/// Whether the vault has a roles chain.
pub async fn has_chain(conn: &mut Conn, vault_id: &str) -> ApiResult<bool> {
    Ok(db::roles::head(conn, vault_id).await?.is_some())
}

/// `GET /v1/vaults/{id}/roles?since=`: for active members and invitees.
pub async fn get(
    State(app): State<Arc<App>>,
    session: AuthSession,
    Path(path): Path<String>,
    uri: Uri,
) -> ApiResult<Json<Value>> {
    let vault_id = vault_id(&path)?;
    let query = parse_query(uri.query(), &["since"])?;
    let since = match query.get("since") {
        None => 0,
        Some(text) => counter(text).ok_or_else(|| ApiError::parameter("since", "invalid value"))?,
    };
    let mut tx = app.db.read.begin().await?;
    db::vaults::membership(&mut tx, vault_id, &session.user_id)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    let statements: Vec<Value> = db::roles::since(&mut tx, vault_id, since)
        .await?
        .into_iter()
        .map(|s| {
            json!({
                "version": s.version,
                "statement": encode_base64url(&s.statement),
                "signature": encode_base64url(&s.signature),
            })
        })
        .collect();
    Ok(Json(json!({ "statements": statements })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppendBody {
    roles: SignedRoles,
}

/// `POST /v1/vaults/{id}/roles`: the first statement of an older vault, or
/// one that only drops owners who left; never a key change.
pub async fn append(
    State(app): State<Arc<App>>,
    session: AuthSession,
    ip: ClientIp,
    _: NoQuery,
    Path(path): Path<String>,
    StrictJson(body): StrictJson<AppendBody>,
) -> ApiResult<StatusCode> {
    let vault_id = vault_id(&path)?;
    let user_id = session.user_id.as_str();
    let now = format_timestamp(app.now());
    let mut tx = app.db.begin().await?;
    require(&mut tx, vault_id, user_id, Need::Owner).await?;
    let vault = db::vaults::vault(&mut tx, vault_id)
        .await?
        .ok_or_else(|| ApiError::new(ErrorCode::NotFound))?;
    let after = After {
        owners: db::roles::owner_keys(&mut tx, vault_id).await?,
        key_version: vault.key_version,
        new_key: false,
    };
    let checked = check(&mut tx, vault_id, user_id, &body.roles, &after).await?;
    store(&mut tx, &app.audit, vault_id, &checked, &now, &ip.hint()).await?;
    let recipients = db::vaults::active_members(&mut tx, vault_id).await?;
    tx.commit().await?;
    app.hub.publish(
        recipients.iter().map(String::as_str),
        &events::vaults_changed(),
    );
    Ok(StatusCode::NO_CONTENT)
}
