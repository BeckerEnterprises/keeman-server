//! `keeman-server user list|disable|enable|reset-2fa`.

use serde_json::json;
use time::OffsetDateTime;

use super::CliResult;
use crate::audit;
use crate::clock::format_timestamp;
use crate::db::{self, Db};
use crate::types::normalize_email;

pub async fn list_command(db: &Db) -> CliResult<()> {
    println!("EMAIL\tCREATED\t2FA\tLAST LOGIN\tSTATE");
    for user in db::users::list(&db.read).await.map_err(|e| e.to_string())? {
        let mut factors = Vec::new();
        if user.totp_enabled {
            factors.push("totp".to_string());
        }
        if user.webauthn_credentials > 0 {
            factors.push(format!("passkeys:{}", user.webauthn_credentials));
        }
        let factors = if factors.is_empty() {
            "none".to_string()
        } else {
            factors.join(",")
        };
        let state = if user.disabled { "disabled" } else { "active" };
        let last_login = user.last_login_at.unwrap_or_else(|| "-".into());
        println!(
            "{}\t{}\t{factors}\t{last_login}\t{state}",
            user.email, user.created_at
        );
    }
    Ok(())
}

/// Disabling revokes all sessions with their tokens and challenges; both
/// directions can be repeated.
pub async fn set_disabled(
    db: &Db,
    now: OffsetDateTime,
    email: &str,
    disabled: bool,
) -> CliResult<()> {
    let email = normalize_email(email);
    let now_text = format_timestamp(now);
    let mut tx = db.begin().await.map_err(|e| e.to_string())?;
    let Some(user_id) = db::users::set_disabled(&mut *tx, &email, disabled, &now_text)
        .await
        .map_err(|e| e.to_string())?
    else {
        return Err("no account with this e-mail address".into());
    };
    if disabled {
        let revoked = db::sessions::revoke_all(&mut tx, &user_id, &now_text)
            .await
            .map_err(|e| e.to_string())?;
        db::challenges::delete_all_for_user(&mut *tx, &user_id)
            .await
            .map_err(|e| e.to_string())?;
        audit::sessions_revoked(&mut tx, &now_text, &user_id, None, &revoked, "admin")
            .await
            .map_err(|e| e.to_string())?;
    }
    let event = if disabled {
        "user_disabled"
    } else {
        "user_enabled"
    };
    audit::log(&mut tx, &now_text, event, Some(&user_id), None, json!({}))
        .await
        .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    println!(
        "{} {}",
        if disabled { "disabled" } else { "enabled" },
        email
    );
    Ok(())
}

/// Removes TOTP, passkeys, backup codes and open second-factor steps; the
/// data stays protected by the master password, sessions stay.
/// Can be repeated.
pub async fn reset_two_factor(db: &Db, now: OffsetDateTime, email: &str) -> CliResult<()> {
    let email = normalize_email(email);
    let now_text = format_timestamp(now);
    let mut tx = db.begin().await.map_err(|e| e.to_string())?;
    let Some(user_id) = db::users::reset_two_factor(&mut tx, &email, &now_text)
        .await
        .map_err(|e| e.to_string())?
    else {
        return Err("no account with this e-mail address".into());
    };
    audit::log(
        &mut tx,
        &now_text,
        "two_factor_reset",
        Some(&user_id),
        None,
        json!({}),
    )
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    println!("second factor removed for {email}");
    Ok(())
}
