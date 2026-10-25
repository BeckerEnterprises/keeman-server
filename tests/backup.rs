//! `backup`, `restore` and `check` through the binary: a backup restored
//! into a fresh data directory gives the same accounts, vaults, objects and
//! attachments; damaged or foreign archives are refused before anything is
//! put in place.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use axum::http::StatusCode;
use keeman_server::config::Config;
use serde_json::{Value, json};
use support::{Account, Req, TestApp, new_uuid, put_op};

const PART: usize = 8 * 1024 * 1024;

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_keeman-server"))
        .env_clear()
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// A directory with `init --dev` already run: config.toml, server_secret,
/// data/ with empty attachments/ and uploads/.
fn initialised() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let output = run(dir.path(), &["init", "--dev"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let config = dir.path().join("config.toml");
    (dir, config)
}

async fn app_on(config: &Path) -> TestApp {
    TestApp::with(
        Config::load(config, &[]).unwrap(),
        tempfile::tempdir().unwrap(),
    )
    .await
}

/// A recognisable pattern; byte `i` is `i * 31 mod 251`.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31) % 251) as u8).collect()
}

/// Uploads `data` as an attachment; completes it unless `complete` is false.
async fn attach(
    t: &TestApp,
    account: &Account,
    vault: &str,
    data: &[u8],
    complete: bool,
) -> String {
    let id = new_uuid();
    let base = format!("/v1/vaults/{vault}/attachments");
    let response = t
        .call(
            Req::post(&base)
                .token(&account.access_token)
                .json(&json!({ "attachment_id": id, "entry_id": new_uuid(), "size": data.len() })),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
    for (i, chunk) in data.chunks(PART).enumerate() {
        let response = t
            .call(
                Req::put(&format!("{base}/{id}/parts/{i}"))
                    .token(&account.access_token)
                    .raw(Some("application/octet-stream"), chunk),
            )
            .await;
        assert_eq!(response.status, StatusCode::NO_CONTENT);
    }
    if complete {
        let response = t
            .call(Req::post(&format!("{base}/{id}/complete")).token(&account.access_token))
            .await;
        assert_eq!(response.status, StatusCode::NO_CONTENT);
    }
    id
}

async fn download(t: &TestApp, account: &Account, vault: &str, id: &str) -> Vec<u8> {
    let response = t
        .call(
            Req::get(&format!("/v1/vaults/{vault}/attachments/{id}")).token(&account.access_token),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    response.body.to_vec()
}

/// Everything an account sees: its vault list and every vault's objects.
async fn state(t: &TestApp, account: &Account) -> Value {
    let response = t
        .call(Req::get("/v1/vaults").token(&account.access_token))
        .await;
    assert_eq!(response.status, StatusCode::OK);
    let vaults = response.json();
    let mut objects = serde_json::Map::new();
    for vault in vaults["vaults"].as_array().unwrap() {
        let id = vault["vault_id"].as_str().unwrap();
        if vault["state"] == "active" {
            let changes = t.changes(account, id, "since=0").await;
            assert_eq!(changes.status, StatusCode::OK);
            objects.insert(id.to_string(), changes.json());
        }
    }
    json!({ "vaults": vaults, "objects": objects })
}

struct Source {
    dir: tempfile::TempDir,
    t: TestApp,
    alice: Account,
    bob: Account,
    vault: String,
    shared: String,
    small: String,
    large: String,
}

/// Two accounts, a private and a shared vault, objects and attachments;
/// with `upload_in_progress`, also an unfinished upload.
async fn source(upload_in_progress: bool) -> Source {
    let (dir, config) = initialised();
    let t = app_on(&config).await;
    let alice = t.register("alice@example.com").await;
    let bob = t.register("bob@example.com").await;
    let vault = t.create_vault(&alice).await;
    let shared = t.create_vault(&alice).await;
    t.share(&alice, &shared, &bob).await;
    let ops: Vec<Value> = (0..5).map(|_| put_op(&new_uuid(), "entry", None)).collect();
    assert_eq!(t.batch(&alice, &vault, ops).await.status, StatusCode::OK);
    let small = attach(&t, &alice, &vault, &pattern(1000), true).await;
    let large = attach(&t, &alice, &shared, &pattern(PART + 4096), true).await;
    if upload_in_progress {
        attach(&t, &alice, &vault, &pattern(100), false).await;
    }
    Source {
        dir,
        t,
        alice,
        bob,
        vault,
        shared,
        small,
        large,
    }
}

fn backup_to(dir: &Path, name: &str) -> PathBuf {
    let archive = dir.join(name);
    let output = run(dir, &["backup", "--out", archive.to_str().unwrap()]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output).trim(), archive.to_str().unwrap());
    archive
}

/// A fresh installation with the source's server secret, as an operator
/// restores it from its separate backup.
fn fresh_target(source: &Source) -> (tempfile::TempDir, PathBuf) {
    let (dir, config) = initialised();
    std::fs::copy(
        source.dir.path().join("server_secret"),
        dir.path().join("server_secret"),
    )
    .unwrap();
    (dir, config)
}

#[tokio::test]
async fn restore_gives_identical_data() {
    let s = source(false).await;
    let before_alice = state(&s.t, &s.alice).await;
    let before_bob = state(&s.t, &s.bob).await;
    let archive = backup_to(s.dir.path(), "backup.tar.zst");
    assert_eq!(mode(&archive), 0o600);
    assert!(
        std::fs::read_dir(s.dir.path()).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with('.')),
        "no temporary files stay behind"
    );

    let (target, config) = fresh_target(&s);
    let output = run(
        target.path(),
        &[
            "restore",
            "--from",
            archive.to_str().unwrap(),
            "--data-dir",
            "data",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("2 accounts, 2 vaults")
            && stdout(&output).contains("2 attachments"),
        "{}",
        stdout(&output)
    );
    let data = target.path().join("data");
    assert_eq!(mode(&data.join("keeman.sqlite")), 0o600);
    assert_eq!(mode(&data.join("attachments")), 0o700);
    assert!(data.join("uploads").is_dir());
    let output = run(target.path(), &["check"]);
    assert!(
        output.status.success(),
        "{}{}",
        stdout(&output),
        stderr(&output)
    );

    let t = app_on(&config).await;
    let alice = t.login(&s.alice).await;
    let bob = t.login(&s.bob).await;
    assert_eq!(state(&t, &alice).await, before_alice);
    assert_eq!(state(&t, &bob).await, before_bob);
    assert_eq!(
        download(&t, &alice, &s.vault, &s.small).await,
        pattern(1000)
    );
    assert_eq!(
        download(&t, &bob, &s.shared, &s.large).await,
        pattern(PART + 4096)
    );
}

/// The entries of an archive, in order.
fn entries(archive: &Path) -> Vec<(String, Vec<u8>)> {
    let decoder = zstd::Decoder::new(std::fs::File::open(archive).unwrap()).unwrap();
    let mut tar = tar::Archive::new(decoder);
    tar.entries()
        .unwrap()
        .map(|entry| {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_str().unwrap().to_string();
            let mut data = Vec::new();
            entry.read_to_end(&mut data).unwrap();
            (path, data)
        })
        .collect()
}

/// Archive entries to write; a `None` body is a symlink.
type Entries = Vec<(String, Option<Vec<u8>>)>;

/// Writes an archive with the given entries.
fn write_archive(archive: &Path, entries: &Entries) {
    let encoder = zstd::Encoder::new(std::fs::File::create(archive).unwrap(), 3).unwrap();
    let mut tar = tar::Builder::new(encoder);
    for (path, data) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o600);
        match data {
            Some(data) => {
                header.set_size(data.len() as u64);
                header.set_entry_type(tar::EntryType::Regular);
                // set_path refuses `..`; an attacker's archive need not.
                let name = &mut header.as_old_mut().name;
                name[..path.len()].copy_from_slice(path.as_bytes());
                header.set_cksum();
                tar.append(&header, data.as_slice()).unwrap();
            }
            None => {
                header.set_size(0);
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_path(path).unwrap();
                header.set_link_name("/etc/passwd").unwrap();
                header.set_cksum();
                tar.append(&header, std::io::empty()).unwrap();
            }
        }
    }
    tar.into_inner().unwrap().finish().unwrap().flush().unwrap();
}

fn assert_refused(source: &Source, archive: &Path, expected: &str) {
    let (target, _) = fresh_target(source);
    let output = run(
        target.path(),
        &[
            "restore",
            "--from",
            archive.to_str().unwrap(),
            "--data-dir",
            "data",
        ],
    );
    assert!(!output.status.success(), "{expected}");
    assert!(stderr(&output).contains(expected), "{}", stderr(&output));
    let data = target.path().join("data");
    let left: Vec<String> = std::fs::read_dir(&data)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        !left
            .iter()
            .any(|n| n == "keeman.sqlite" || n.starts_with(".restore-")),
        "nothing is put in place: {left:?}"
    );
    assert!(!target.path().join("passwd").exists());
}

#[tokio::test]
async fn damaged_or_foreign_archives_are_refused() {
    let s = source(true).await;
    let archive = backup_to(s.dir.path(), "backup.tar.zst");
    let good = entries(&archive);
    let rewrite = |name: &str, change: &dyn Fn(&mut Entries)| {
        let mut list: Entries = good
            .iter()
            .map(|(p, d)| (p.clone(), Some(d.clone())))
            .collect();
        change(&mut list);
        let path = s.dir.path().join(name);
        write_archive(&path, &list);
        path
    };

    let flipped = rewrite("flipped.tar.zst", &|list| {
        let db = list.iter_mut().find(|(p, _)| p == "keeman.sqlite").unwrap();
        let data = db.1.as_mut().unwrap();
        let middle = data.len() / 2;
        data[middle] ^= 0x01;
    });
    assert_refused(&s, &flipped, "keeman.sqlite does not match the manifest");

    let dropped = rewrite("dropped.tar.zst", &|list| {
        list.retain(|(p, _)| !p.starts_with("attachments/"));
    });
    assert_refused(&s, &dropped, "is missing from the archive");

    let escaping = rewrite("escaping.tar.zst", &|list| {
        list.insert(0, ("../passwd".into(), Some(b"x".to_vec())));
    });
    assert_refused(&s, &escaping, "unexpected archive entry ../passwd");

    let linked = rewrite("linked.tar.zst", &|list| {
        list.insert(0, ("keeman.sqlite".into(), None));
    });
    assert_refused(&s, &linked, "is not a regular file");

    let extra = rewrite("extra.tar.zst", &|list| {
        let id = new_uuid();
        let path = format!("attachments/{}/{id}.bin", &id[..2]);
        list.insert(0, (path, Some(b"x".to_vec())));
    });
    assert_refused(&s, &extra, "is in the archive but not in the manifest");

    let unmanifested = rewrite("nomanifest.tar.zst", &|list| {
        list.retain(|(p, _)| p != "manifest.json");
    });
    assert_refused(&s, &unmanifested, "archive without manifest");

    let newer = rewrite("newer.tar.zst", &|list| {
        let manifest = list.iter_mut().find(|(p, _)| p == "manifest.json").unwrap();
        let mut value: Value = serde_json::from_slice(manifest.1.as_ref().unwrap()).unwrap();
        value["version"] = json!(2);
        manifest.1 = Some(serde_json::to_vec(&value).unwrap());
    });
    assert_refused(
        &s,
        &newer,
        "unsupported backup format keeman-backup version 2",
    );

    let garbage = s.dir.path().join("garbage.tar.zst");
    std::fs::write(&garbage, b"not an archive").unwrap();
    let (target, _) = fresh_target(&s);
    let output = run(
        target.path(),
        &[
            "restore",
            "--from",
            garbage.to_str().unwrap(),
            "--data-dir",
            "data",
        ],
    );
    assert!(!output.status.success());
}

#[tokio::test]
async fn restore_needs_an_empty_target_and_backup_never_overwrites() {
    let s = source(false).await;
    let archive = backup_to(s.dir.path(), "backup.tar.zst");

    // The source's own data directory is not empty.
    let output = run(
        s.dir.path(),
        &[
            "restore",
            "--from",
            archive.to_str().unwrap(),
            "--data-dir",
            "data",
        ],
    );
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("is not empty"),
        "{}",
        stderr(&output)
    );

    // A missing target is created; one with a stray file is refused.
    let fresh = tempfile::tempdir().unwrap();
    let output = run(
        fresh.path(),
        &[
            "restore",
            "--from",
            archive.to_str().unwrap(),
            "--data-dir",
            "new",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(mode(&fresh.path().join("new")), 0o700);
    let (target, _) = fresh_target(&s);
    std::fs::write(target.path().join("data/uploads/stray"), b"x").unwrap();
    let output = run(
        target.path(),
        &[
            "restore",
            "--from",
            archive.to_str().unwrap(),
            "--data-dir",
            "data",
        ],
    );
    assert!(!output.status.success());

    let output = run(
        s.dir.path(),
        &["backup", "--out", archive.to_str().unwrap()],
    );
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("already exists"),
        "{}",
        stderr(&output)
    );
}

#[tokio::test]
async fn a_missing_file_is_reported_not_fatal() {
    let s = source(false).await;
    let blob = s.dir.path().join(format!(
        "data/attachments/{}/{}.bin",
        &s.small[..2],
        s.small
    ));
    std::fs::remove_file(blob).unwrap();
    let archive = s.dir.path().join("backup.tar.zst");
    let output = run(
        s.dir.path(),
        &["backup", "--out", archive.to_str().unwrap()],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains(&s.small), "{}", stderr(&output));
    let manifest: Value = serde_json::from_slice(
        &entries(&archive)
            .into_iter()
            .find(|(p, _)| p == "manifest.json")
            .unwrap()
            .1,
    )
    .unwrap();
    assert_eq!(manifest["missing"], json!([s.small]));
    assert_eq!(manifest["format"], "keeman-backup");
    assert_eq!(manifest["version"], 1);

    let (target, _) = fresh_target(&s);
    let output = run(
        target.path(),
        &[
            "restore",
            "--from",
            archive.to_str().unwrap(),
            "--data-dir",
            "data",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains(&s.small));
    let output = run(target.path(), &["check"]);
    assert!(!output.status.success());
    assert!(
        stdout(&output).contains(&format!(
            "attachment {} is complete but has no file",
            s.small
        )),
        "{}",
        stdout(&output)
    );
}

#[tokio::test]
async fn backups_in_a_folder_are_pruned() {
    let s = source(false).await;
    let folder = s.dir.path().join("backups");
    std::fs::create_dir(&folder).unwrap();
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o700)).unwrap();
    for name in [
        "keeman-20260101-120000.tar.zst",
        "keeman-20260101-130000.tar.zst",
        "keeman-20260102-090000.tar.zst",
        "keeman-20250601-000000.tar.zst",
        "notes.txt",
    ] {
        std::fs::write(folder.join(name), b"x").unwrap();
    }
    let output = run(
        s.dir.path(),
        &[
            "backup",
            "--dir",
            "backups",
            "--keep-daily",
            "1",
            "--keep-weekly",
            "3",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let written = PathBuf::from(stdout(&output).trim());
    let name = written.file_name().unwrap().to_str().unwrap().to_string();
    assert!(
        name.starts_with("keeman-") && name.ends_with(".tar.zst"),
        "{name}"
    );
    let mut left: Vec<String> = std::fs::read_dir(&folder)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    let mut expected = vec![
        "keeman-20250601-000000.tar.zst".to_string(),
        "keeman-20260102-090000.tar.zst".to_string(),
        name,
        "notes.txt".to_string(),
    ];
    expected.sort();
    assert_eq!(left, expected);

    let output = run(s.dir.path(), &["backup", "--keep-daily", "3"]);
    assert!(!output.status.success(), "retention needs --dir");
}

#[tokio::test]
async fn check_reports_every_problem_and_changes_nothing() {
    let s = source(false).await;
    let output = run(s.dir.path(), &["check"]);
    assert!(
        output.status.success(),
        "{}{}",
        stdout(&output),
        stderr(&output)
    );
    assert!(stdout(&output).contains("ok: no problems found"));

    let data = s.dir.path().join("data");
    let small = data.join(format!("attachments/{}/{}.bin", &s.small[..2], s.small));
    let large = data.join(format!("attachments/{}/{}.bin", &s.large[..2], s.large));
    std::fs::set_permissions(&small, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::remove_file(&large).unwrap();
    let orphan = new_uuid();
    let orphan_dir = data.join(format!("attachments/{}", &orphan[..2]));
    std::fs::create_dir_all(&orphan_dir).unwrap();
    std::fs::set_permissions(&orphan_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(orphan_dir.join(format!("{orphan}.bin")), b"x").unwrap();
    std::fs::set_permissions(
        orphan_dir.join(format!("{orphan}.bin")),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let stray = new_uuid();
    std::fs::create_dir(data.join(format!("uploads/{stray}"))).unwrap();
    std::fs::set_permissions(
        data.join(format!("uploads/{stray}")),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();

    let output = run(s.dir.path(), &["check"]);
    assert!(!output.status.success());
    let report = stdout(&output);
    for expected in [
        format!("{}.bin must not be accessible by group or others", s.small),
        format!("attachment {} is complete but has no file", s.large),
        format!("{orphan}.bin belongs to no complete attachment"),
        format!("uploads/{stray} belongs to no upload in progress"),
    ] {
        assert!(report.contains(&expected), "{expected}\n{report}");
    }
    assert!(
        stderr(&output).contains("4 problem(s) found"),
        "{}",
        stderr(&output)
    );
    assert!(
        data.join(format!("uploads/{stray}")).exists(),
        "check changes nothing"
    );
}

#[tokio::test]
async fn backup_refuses_a_missing_or_unmigrated_database() {
    let (dir, _) = initialised();
    let output = run(dir.path(), &["backup", "--out", "x.tar.zst"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("no database"),
        "{}",
        stderr(&output)
    );

    let db = dir.path().join("data/keeman.sqlite");
    std::fs::write(&db, b"").unwrap();
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
    let output = run(dir.path(), &["backup", "--out", "x.tar.zst"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("migrations"),
        "{}",
        stderr(&output)
    );
    assert!(!dir.path().join("x.tar.zst").exists());
    assert!(!dir.path().join("x.tar.zst.partial").exists());
}
