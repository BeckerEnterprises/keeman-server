//! `keeman-server invite create|list|revoke`.

use serde_json::json;
use time::{Duration, OffsetDateTime};

use super::CliResult;
use crate::audit;
use crate::clock::format_timestamp;
use crate::crypto::new_token;
use crate::db::{self, Db};

pub const NOTE_MAX_CHARS: usize = 200;

/// `<n>m`, `<n>h` or `<n>d`, between one minute and 365 days.
pub fn parse_expires(text: &str) -> CliResult<Duration> {
    let invalid = || format!("--expires {text}: expected <n>m, <n>h or <n>d, at most 365d");
    let unit = text.chars().last().ok_or_else(invalid)?;
    let number: i64 = text[..text.len() - unit.len_utf8()]
        .parse()
        .map_err(|_| invalid())?;
    let duration = match unit {
        'm' => Duration::minutes(number),
        'h' => Duration::hours(number),
        'd' => Duration::days(number),
        _ => return Err(invalid()),
    };
    if duration < Duration::minutes(1) || duration > Duration::days(365) {
        return Err(invalid());
    }
    Ok(duration)
}

/// Creates an invite and returns its code; only the hash is stored.
pub async fn create(
    db: &Db,
    now: OffsetDateTime,
    expires: Duration,
    note: Option<&str>,
) -> CliResult<String> {
    if note.is_some_and(|n| n.chars().count() > NOTE_MAX_CHARS) {
        return Err(format!(
            "--note must have at most {NOTE_MAX_CHARS} characters"
        ));
    }
    let code = new_token().map_err(|e| e.to_string())?;
    let id = uuid::Uuid::now_v7().to_string();
    let now_text = format_timestamp(now);
    let mut tx = db.begin().await.map_err(|e| e.to_string())?;
    db::invites::insert(
        &mut *tx,
        &id,
        &code.hash,
        note,
        &now_text,
        &format_timestamp(now + expires),
    )
    .await
    .map_err(|e| e.to_string())?;
    audit::log(
        &mut tx,
        &now_text,
        "invite_created",
        None,
        None,
        json!({ "invite_id": id }),
    )
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(code.text)
}

pub async fn create_command(
    db: &Db,
    now: OffsetDateTime,
    expires: &str,
    note: Option<&str>,
) -> CliResult<()> {
    let code = create(db, now, parse_expires(expires)?, note).await?;
    println!("{code}");
    Ok(())
}

pub async fn list_command(db: &Db, now: OffsetDateTime) -> CliResult<()> {
    let now_text = format_timestamp(now);
    println!("ID\tSTATE\tCREATED\tEXPIRES\tNOTE");
    for invite in db::invites::list(&db.read)
        .await
        .map_err(|e| e.to_string())?
    {
        let state = if invite.used_at.is_some() {
            "used"
        } else if invite.expires_at <= now_text {
            "expired"
        } else {
            "unused"
        };
        let note = invite
            .note
            .unwrap_or_default()
            .replace(char::is_control, " ");
        println!(
            "{}\t{state}\t{}\t{}\t{note}",
            invite.id, invite.created_at, invite.expires_at
        );
    }
    Ok(())
}

/// Deletes an unused invite; used ones stay for auditing.
pub async fn revoke(db: &Db, now: OffsetDateTime, id: &str) -> CliResult<()> {
    let mut tx = db.begin().await.map_err(|e| e.to_string())?;
    if db::invites::revoke_unused(&mut *tx, id)
        .await
        .map_err(|e| e.to_string())?
        == 0
    {
        return Err(format!("no unused invite with ID {id}"));
    }
    audit::log(
        &mut tx,
        &format_timestamp(now),
        "invite_revoked",
        None,
        None,
        json!({ "invite_id": id }),
    )
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    println!("revoked invite {id}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_units() {
        assert_eq!(parse_expires("7d"), Ok(Duration::days(7)));
        assert_eq!(parse_expires("12h"), Ok(Duration::hours(12)));
        assert_eq!(parse_expires("30m"), Ok(Duration::minutes(30)));
        assert_eq!(parse_expires("365d"), Ok(Duration::days(365)));
        for bad in ["", "d", "0d", "366d", "-1d", "7", "7w", "1.5d", "7dd"] {
            assert!(parse_expires(bad).is_err(), "{bad}");
        }
    }
}
