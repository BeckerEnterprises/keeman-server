//! Which backups of a folder to keep: the newest backup of each of the
//! most recent days and of each of the most recent ISO weeks (UTC), read
//! from the timestamp in the file name. Other files are never touched.

use std::collections::BTreeSet;

use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime, UtcOffset};

const PREFIX: &str = "keeman-";
const SUFFIX: &str = ".tar.zst";

/// `keeman-<YYYYMMDD-HHMMSS>.tar.zst` for a backup taken at `now`.
pub fn file_name(now: OffsetDateTime) -> String {
    let t = now.to_offset(UtcOffset::UTC);
    format!(
        "{PREFIX}{:04}{:02}{:02}-{:02}{:02}{:02}{SUFFIX}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// The time in a backup's file name, or `None` for other files.
pub fn parse(name: &str) -> Option<PrimitiveDateTime> {
    let stamp = name.strip_prefix(PREFIX)?.strip_suffix(SUFFIX)?;
    let format = format_description!("[year][month][day]-[hour][minute][second]");
    if stamp.len() != 15 {
        return None;
    }
    PrimitiveDateTime::parse(stamp, format).ok()
}

/// The backups among `names` to delete; `keep` (the one just written) always
/// stays.
pub fn to_delete(
    names: &[String],
    keep_daily: usize,
    keep_weekly: usize,
    keep: &str,
) -> Vec<String> {
    let mut backups: Vec<(PrimitiveDateTime, &String)> = names
        .iter()
        .filter_map(|name| parse(name).map(|time| (time, name)))
        .collect();
    // Newest first, so the first backup of a day or week is its newest.
    backups.sort_by(|a, b| b.cmp(a));
    let mut kept: BTreeSet<&str> = BTreeSet::new();
    kept.insert(keep);
    let mut days = Vec::new();
    let mut weeks = Vec::new();
    for (time, name) in &backups {
        let day = time.date();
        if !days.contains(&day) {
            if days.len() < keep_daily {
                kept.insert(name.as_str());
            }
            days.push(day);
        }
        let (year, week, _) = day.to_iso_week_date();
        if !weeks.contains(&(year, week)) {
            if weeks.len() < keep_weekly {
                kept.insert(name.as_str());
            }
            weeks.push((year, week));
        }
    }
    backups
        .into_iter()
        .filter(|(_, name)| !kept.contains(name.as_str()))
        .map(|(_, name)| name.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|n| n.to_string()).collect()
    }

    #[test]
    fn names_carry_the_utc_time() {
        let name = file_name(datetime!(2026-10-25 14:03:09 +02:00));
        assert_eq!(name, "keeman-20261025-120309.tar.zst");
        assert_eq!(parse(&name), Some(datetime!(2026-10-25 12:03:09)));
        for other in [
            "keeman-20261025-120309.tar",
            "keeman-20261025-1203.tar.zst",
            "keeman-20261325-120309.tar.zst",
            "x-keeman-20261025-120309.tar.zst",
            "notes.txt",
        ] {
            assert_eq!(parse(other), None, "{other}");
        }
    }

    #[test]
    fn keeps_the_newest_per_day_and_per_week() {
        let all = names(&[
            "keeman-20261025-120000.tar.zst", // today, newest
            "keeman-20261025-060000.tar.zst", // today, older
            "keeman-20261024-120000.tar.zst",
            "keeman-20261023-120000.tar.zst",
            "keeman-20261012-120000.tar.zst", // week 42
            "keeman-20261011-120000.tar.zst", // week 41
            "keeman-20261001-120000.tar.zst", // week 40
            "notes.txt",
        ]);
        let deleted = to_delete(&all, 2, 3, "keeman-20261025-120000.tar.zst");
        assert_eq!(
            deleted,
            names(&[
                "keeman-20261025-060000.tar.zst",
                "keeman-20261023-120000.tar.zst",
                "keeman-20261001-120000.tar.zst",
            ])
        );
    }

    #[test]
    fn iso_weeks_cross_years_and_the_new_backup_stays() {
        let all = names(&[
            "keeman-20260101-000000.tar.zst", // 2026-W01
            "keeman-20251229-000000.tar.zst", // also 2026-W01
            "keeman-20251228-000000.tar.zst", // 2025-W52
        ]);
        assert_eq!(
            to_delete(&all, 0, 2, "keeman-20260101-000000.tar.zst"),
            names(&["keeman-20251229-000000.tar.zst"])
        );
        assert_eq!(
            to_delete(&all, 0, 0, "keeman-20260101-000000.tar.zst"),
            names(&[
                "keeman-20251229-000000.tar.zst",
                "keeman-20251228-000000.tar.zst"
            ])
        );
    }
}
