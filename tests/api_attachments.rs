//! Attachments: upload in parts, complete, download with a
//! range, delete, transfer, quota and cleanup. Blobs are opaque patterns;
//! the server never decrypts them.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::os::unix::fs::PermissionsExt;

use axum::http::StatusCode;
use serde_json::json;
use support::{Account, Req, TestApp, TestResponse, delete_op, new_uuid, put_op};
use time::Duration;

const PART: usize = 8 * 1024 * 1024;

/// A recognisable pattern; byte `i` is `i * 31 mod 251`.
fn blob(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31) % 251) as u8).collect()
}

fn base(vault: &str, id: &str) -> String {
    format!("/v1/vaults/{vault}/attachments/{id}")
}

impl TestApp {
    async fn create_attachment(
        &self,
        account: &Account,
        vault: &str,
        id: &str,
        size: usize,
    ) -> TestResponse {
        self.call(
            Req::post(&format!("/v1/vaults/{vault}/attachments"))
                .token(&account.access_token)
                .json(&json!({ "attachment_id": id, "entry_id": new_uuid(), "size": size })),
        )
        .await
    }

    async fn put_part(
        &self,
        account: &Account,
        vault: &str,
        id: &str,
        part: usize,
        bytes: &[u8],
    ) -> TestResponse {
        self.call(
            Req::put(&format!("{}/parts/{part}", base(vault, id)))
                .token(&account.access_token)
                .raw(Some("application/octet-stream"), bytes),
        )
        .await
    }

    async fn complete(&self, account: &Account, vault: &str, id: &str) -> TestResponse {
        self.call(Req::post(&format!("{}/complete", base(vault, id))).token(&account.access_token))
            .await
    }

    async fn download(
        &self,
        account: &Account,
        vault: &str,
        id: &str,
        range: Option<&str>,
    ) -> TestResponse {
        let mut request = Req::get(&base(vault, id)).token(&account.access_token);
        if let Some(range) = range {
            request = request.header("range", range);
        }
        self.call(request).await
    }

    async fn transfer(
        &self,
        account: &Account,
        vault: &str,
        id: &str,
        target: &str,
        entry: &str,
    ) -> TestResponse {
        self.call(
            Req::post(&format!("{}/transfer", base(vault, id)))
                .token(&account.access_token)
                .json(&json!({ "target_vault_id": target, "target_entry_id": entry })),
        )
        .await
    }

    /// Uploads all parts of `data` without completing.
    async fn upload_parts(&self, account: &Account, vault: &str, id: &str, data: &[u8]) {
        let response = self.create_attachment(account, vault, id, data.len()).await;
        assert_eq!(response.status, StatusCode::CREATED, "{}", response.text());
        let parts = response.json()["parts"].as_u64().unwrap() as usize;
        assert_eq!(parts, data.len().div_ceil(PART));
        for (i, chunk) in data.chunks(PART).enumerate() {
            let response = self.put_part(account, vault, id, i, chunk).await;
            assert_eq!(
                response.status,
                StatusCode::NO_CONTENT,
                "{}",
                response.text()
            );
        }
    }

    /// A complete attachment with `data`; returns its ID.
    async fn stored(&self, account: &Account, vault: &str, data: &[u8]) -> String {
        let id = new_uuid();
        self.upload_parts(account, vault, &id, data).await;
        let response = self.complete(account, vault, &id).await;
        assert_eq!(
            response.status,
            StatusCode::NO_CONTENT,
            "{}",
            response.text()
        );
        id
    }

    fn data_path(&self, path: &str) -> std::path::PathBuf {
        self.dir.path().join("data").join(path)
    }

    fn blob_path(&self, id: &str) -> std::path::PathBuf {
        self.data_path(&format!("attachments/{}/{id}.bin", &id[..2]))
    }
}

async fn setup() -> (TestApp, Account, String) {
    let t = TestApp::new().await;
    let alice = t.register("alice@example.com").await;
    let vault = t.create_vault(&alice).await;
    (t, alice, vault)
}

#[tokio::test]
async fn files_come_back_bit_for_bit() {
    let (t, alice, vault) = setup().await;
    // Blob sizes: an empty file's blob, then around one and two parts.
    for len in [42, 43, 65_536, 65_537, PART, PART + 1, 45 * 1024 * 1024] {
        let data = blob(len);
        let id = t.stored(&alice, &vault, &data).await;
        let response = t.download(&alice, &vault, &id, None).await;
        assert_eq!(response.status, StatusCode::OK, "{len}");
        assert_eq!(response.body.len(), len);
        assert!(response.body.as_ref() == data.as_slice(), "{len}");
        assert_eq!(
            response.header("content-type").as_deref(),
            Some("application/octet-stream")
        );
        assert_eq!(response.header("accept-ranges").as_deref(), Some("bytes"));
        assert_eq!(
            response.header("cache-control").as_deref(),
            Some("no-store")
        );
        assert_eq!(
            response.header("content-length").as_deref(),
            Some(len.to_string().as_str())
        );
    }
    // Complete blobs are 0600 in 0700 directories; no parts stay behind.
    let id = t.stored(&alice, &vault, &blob(100)).await;
    let mode =
        |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&t.blob_path(&id)), 0o600);
    assert_eq!(mode(t.blob_path(&id).parent().unwrap()), 0o700);
    assert_eq!(mode(&t.data_path("attachments")), 0o700);
    assert_eq!(mode(&t.data_path("uploads")), 0o700);
    assert!(!t.data_path(&format!("uploads/{id}")).exists());
}

#[tokio::test]
async fn serves_a_single_range() {
    let (t, alice, vault) = setup().await;
    let data = blob(1000);
    let id = t.stored(&alice, &vault, &data).await;
    for (range, first, last) in [
        ("bytes=0-9", 0, 9),
        ("bytes=990-2000", 990, 999),
        ("bytes=10-", 10, 999),
        ("bytes=-5", 995, 999),
    ] {
        let response = t.download(&alice, &vault, &id, Some(range)).await;
        assert_eq!(response.status, StatusCode::PARTIAL_CONTENT, "{range}");
        assert!(response.body.as_ref() == &data[first..=last], "{range}");
        assert_eq!(
            response.header("content-range").as_deref(),
            Some(format!("bytes {first}-{last}/1000").as_str())
        );
    }
    let response = t.download(&alice, &vault, &id, Some("bytes=1000-")).await;
    assert_eq!(response.status, StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(response.code(), "range_not_satisfiable");
    assert_eq!(
        response.header("content-range").as_deref(),
        Some("bytes */1000")
    );
    for ignored in ["bytes=0-1,5-6", "bytes=9-1", "pages=1-2"] {
        let response = t.download(&alice, &vault, &id, Some(ignored)).await;
        assert_eq!(response.status, StatusCode::OK, "{ignored}");
        assert_eq!(response.body.len(), 1000);
    }
}

#[tokio::test]
async fn checks_parts_before_and_after_completion() {
    let (t, alice, vault) = setup().await;
    let data = blob(PART + 10);
    let id = new_uuid();
    let response = t.create_attachment(&alice, &vault, &id, data.len()).await;
    assert_eq!(response.status, StatusCode::CREATED);
    assert_eq!(response.json(), json!({ "part_size": PART, "parts": 2 }));

    // Wrong size, index out of range, wrong or missing content type, too large.
    let response = t.put_part(&alice, &vault, &id, 1, &data[..9]).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    let response = t.put_part(&alice, &vault, &id, 2, &data[..10]).await;
    assert_eq!(response.field_error().0, "part");
    let response = t.put_part(&alice, &vault, &id, 0, &data[PART..]).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    let path = format!("{}/parts/1", base(&vault, &id));
    for content_type in [Some("application/json"), None] {
        let response = t
            .call(
                Req::put(&path)
                    .token(&alice.access_token)
                    .raw(content_type, &data[PART..]),
            )
            .await;
        assert_eq!(response.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let response = t
        .put_part(&alice, &vault, &id, 0, &blob(PART + 64 * 1024 + 1))
        .await;
    assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
    let response = t.put_part(&alice, &vault, &id, 0, &data[..PART]).await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    let response = t
        .call(
            Req::put(&format!("{}/parts/01", base(&vault, &id)))
                .token(&alice.access_token)
                .raw(Some("application/octet-stream"), &data[PART..]),
        )
        .await;
    assert_eq!(response.field_error().0, "part");

    // Missing part, then a replaced part, then complete twice.
    let response = t.complete(&alice, &vault, &id).await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(response.code(), "attachment_incomplete");
    let response = t.download(&alice, &vault, &id, None).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    let wrong: Vec<u8> = vec![0; 10];
    t.put_part(&alice, &vault, &id, 1, &wrong).await;
    let response = t.put_part(&alice, &vault, &id, 1, &data[PART..]).await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    assert_eq!(
        t.complete(&alice, &vault, &id).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        t.complete(&alice, &vault, &id).await.status,
        StatusCode::NO_CONTENT
    );
    let response = t.put_part(&alice, &vault, &id, 1, &data[PART..]).await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    let response = t.download(&alice, &vault, &id, None).await;
    assert!(response.body.as_ref() == data.as_slice());
}

#[tokio::test]
async fn validates_new_uploads() {
    let t = TestApp::with_config("[limits]\nattachment_max_bytes = 65536\n").await;
    let alice = t.register("alice@example.com").await;
    let vault = t.create_vault(&alice).await;
    let id = new_uuid();
    let response = t.create_attachment(&alice, &vault, &id, 41).await;
    assert_eq!(response.field_error().0, "/size");
    // The largest blob for 64 KiB files: 65536 + 17 × 2 + 25.
    let response = t.create_attachment(&alice, &vault, &id, 65_596).await;
    assert_eq!(response.code(), "attachment_too_large");
    let response = t.create_attachment(&alice, &vault, &id, 65_595).await;
    assert_eq!(response.status, StatusCode::CREATED);
    let response = t.create_attachment(&alice, &vault, &id, 100).await;
    assert_eq!(response.code(), "conflict");
    let response = t
        .call(
            Req::post(&format!("/v1/vaults/{vault}/attachments"))
                .token(&alice.access_token)
                .json(&json!({ "attachment_id": new_uuid(), "entry_id": new_uuid(), "size": 100, "name": "x" })),
        )
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    let response = t
        .call(
            Req::get(&format!(
                "/v1/vaults/{vault}/attachments/{}",
                id.to_uppercase()
            ))
            .token(&alice.access_token),
        )
        .await;
    assert_eq!(response.field_error().0, "attachment_id");
}

#[tokio::test]
async fn only_active_members_reach_attachments() {
    let (t, alice, vault) = setup().await;
    let id = t.stored(&alice, &vault, &blob(100)).await;
    let bob = t.register("bob@example.com").await;
    let paths = [
        Req::get(&base(&vault, &id)),
        Req::delete(&base(&vault, &id)),
        Req::post(&format!("{}/complete", base(&vault, &id))),
    ];
    for request in paths {
        let response = t.call(request.token(&bob.access_token)).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);
    }
    t.add_member(&vault, &bob, "member", "pending").await;
    let response = t.download(&bob, &vault, &id, None).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    t.sql(&format!(
        "UPDATE memberships SET state = 'active', key_wrapped = X'01' WHERE user_id = '{}'",
        bob.user_id
    ))
    .await;
    assert_eq!(
        t.download(&bob, &vault, &id, None).await.status,
        StatusCode::OK
    );
    // An attachment of another vault is unknown here.
    let other = t.create_vault(&bob).await;
    let response = t.download(&bob, &other, &id, None).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn deletes_in_any_state() {
    let (t, alice, vault) = setup().await;
    let done = t.stored(&alice, &vault, &blob(100)).await;
    let running = new_uuid();
    t.upload_parts(&alice, &vault, &running, &blob(100)).await;
    for id in [&done, &running] {
        let response = t
            .call(Req::delete(&base(&vault, id)).token(&alice.access_token))
            .await;
        assert_eq!(response.status, StatusCode::NO_CONTENT);
        let response = t
            .call(Req::delete(&base(&vault, id)).token(&alice.access_token))
            .await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);
    }
    assert!(!t.blob_path(&done).exists());
    assert!(!t.data_path(&format!("uploads/{running}")).exists());
    assert_eq!(t.count("SELECT COUNT(*) FROM attachments").await, 0);
}

#[tokio::test]
async fn transfers_between_vaults_and_entries() {
    let (t, alice, vault) = setup().await;
    let other = t.create_vault(&alice).await;
    let data = blob(500);
    let id = t.stored(&alice, &vault, &data).await;
    let entry = new_uuid();

    let response = t.transfer(&alice, &vault, &id, &other, &entry).await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    assert_eq!(
        t.download(&alice, &vault, &id, None).await.status,
        StatusCode::NOT_FOUND
    );
    let response = t.download(&alice, &other, &id, None).await;
    assert!(response.body.as_ref() == data.as_slice());
    // Repeating the same transfer is fine; another target is not.
    let response = t.transfer(&alice, &vault, &id, &other, &entry).await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    let response = t.transfer(&alice, &vault, &id, &other, &new_uuid()).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    // Within the same vault only the entry changes.
    let next = new_uuid();
    let response = t.transfer(&alice, &other, &id, &other, &next).await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    let entry_of = t
        .count(&format!(
            "SELECT COUNT(*) FROM attachments WHERE id = '{id}' AND vault_id = '{other}' AND entry_id = '{next}'"
        ))
        .await;
    assert_eq!(entry_of, 1);

    // Uploads in progress cannot move; foreign targets are unknown.
    let running = new_uuid();
    t.upload_parts(&alice, &vault, &running, &blob(100)).await;
    let response = t.transfer(&alice, &vault, &running, &other, &entry).await;
    assert_eq!(response.code(), "conflict");
    let bob = t.register("bob@example.com").await;
    let foreign = t.create_vault(&bob).await;
    let response = t.transfer(&alice, &other, &id, &foreign, &entry).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    let response = t.transfer(&bob, &other, &id, &foreign, &entry).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn quota_counts_against_the_vault_creator() {
    // 1000 bytes for attachments plus the objects of Alice's two vaults
    // (3 × 300 bytes each), which count as well.
    let t = TestApp::with_config("[limits]\nuser_quota_bytes = 2800\n").await;
    let alice = t.register("alice@example.com").await;
    let vault = t.create_vault(&alice).await;
    let second = t.create_vault(&alice).await;
    t.stored(&alice, &vault, &blob(600)).await;
    // Uploads in progress count, across all vaults of the account.
    t.upload_parts(&alice, &second, &new_uuid(), &blob(300))
        .await;
    let response = t.create_attachment(&alice, &second, &new_uuid(), 101).await;
    assert_eq!(response.status, StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(response.code(), "quota_exceeded");
    let response = t.create_attachment(&alice, &second, &new_uuid(), 100).await;
    assert_eq!(response.status, StatusCode::CREATED);

    // Bob's vault counts against Bob, also when Alice uploads.
    let bob = t.register("bob@example.com").await;
    let shared = t.create_vault(&bob).await;
    t.add_member(&shared, &alice, "member", "active").await;
    let id = t.stored(&alice, &shared, &blob(900)).await;
    // Moving it into Alice's full vault exceeds her quota.
    let response = t.transfer(&alice, &shared, &id, &vault, &new_uuid()).await;
    assert_eq!(response.code(), "quota_exceeded");

    // Once Bob is no owner any more, the oldest remaining owner pays.
    t.sql(&format!(
        "UPDATE memberships SET role = 'owner' WHERE user_id = '{}'",
        alice.user_id
    ))
    .await;
    t.sql(&format!(
        "UPDATE memberships SET role = 'member' WHERE user_id = '{}'",
        bob.user_id
    ))
    .await;
    let response = t.create_attachment(&bob, &shared, &new_uuid(), 42).await;
    assert_eq!(response.code(), "quota_exceeded");
    // Within Alice's own vaults no quota check applies to a transfer.
    let response = t.transfer(&alice, &shared, &id, &vault, &new_uuid()).await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn deleting_entries_vaults_and_accounts_deletes_attachments() {
    let (t, alice, vault) = setup().await;
    let entry = new_uuid();
    let response = t
        .batch(&alice, &vault, vec![put_op(&entry, "entry", None)])
        .await;
    let revision = response.json()["vault_revision"].as_i64().unwrap();
    let mine = t.stored(&alice, &vault, &blob(100)).await;
    let other = t.stored(&alice, &vault, &blob(100)).await;
    let running = new_uuid();
    t.upload_parts(&alice, &vault, &running, &blob(100)).await;
    for id in [&mine, &running] {
        let response = t.transfer(&alice, &vault, id, &vault, &entry).await;
        if id == &mine {
            assert_eq!(response.status, StatusCode::NO_CONTENT);
        }
    }
    t.sql(&format!(
        "UPDATE attachments SET entry_id = '{entry}' WHERE id = '{running}'"
    ))
    .await;
    let response = t
        .batch(&alice, &vault, vec![delete_op(&entry, revision)])
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(
        t.download(&alice, &vault, &mine, None).await.status,
        StatusCode::NOT_FOUND
    );
    assert!(!t.blob_path(&mine).exists());
    assert!(!t.data_path(&format!("uploads/{running}")).exists());
    assert_eq!(
        t.download(&alice, &vault, &other, None).await.status,
        StatusCode::OK
    );

    let reauth = t.reauth(&alice).await;
    let response = t
        .call(
            Req::delete(&format!("/v1/vaults/{vault}"))
                .token(&alice.access_token)
                .reauth(&reauth),
        )
        .await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    assert!(!t.blob_path(&other).exists());

    let second = t.create_vault(&alice).await;
    let last = t.stored(&alice, &second, &blob(100)).await;
    let reauth = t.reauth(&alice).await;
    let response = t
        .call(
            Req::delete("/v1/me")
                .token(&alice.access_token)
                .reauth(&reauth),
        )
        .await;
    assert_eq!(response.status, StatusCode::NO_CONTENT);
    assert!(!t.blob_path(&last).exists());
    assert_eq!(t.count("SELECT COUNT(*) FROM attachments").await, 0);
}

#[tokio::test]
async fn cleanup_removes_abandoned_uploads_and_reports_orphans() {
    let (t, alice, vault) = setup().await;
    let old = new_uuid();
    t.upload_parts(&alice, &vault, &old, &blob(100)).await;
    let done = t.stored(&alice, &vault, &blob(100)).await;
    t.advance(Duration::hours(23));
    let alice = t.login(&alice).await;
    let young = new_uuid();
    t.upload_parts(&alice, &vault, &young, &blob(100)).await;
    t.advance(Duration::hours(2));
    let alice = t.login(&alice).await;

    let removed = keeman_server::jobs::cleanup(&t.app).await.unwrap();
    assert_eq!(removed.attachments, 1);
    assert!(!t.data_path(&format!("uploads/{old}")).exists());
    assert!(t.data_path(&format!("uploads/{young}")).exists());
    assert_eq!(
        t.complete(&alice, &vault, &old).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        t.complete(&alice, &vault, &young).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        t.download(&alice, &vault, &done, None).await.status,
        StatusCode::OK
    );

    // A blob without row and a row without blob are only reported; leftover
    // upload directories go.
    let stray = new_uuid();
    std::fs::create_dir_all(t.data_path(&format!("attachments/{}", &stray[..2]))).unwrap();
    std::fs::write(t.blob_path(&stray), b"orphan").unwrap();
    std::fs::create_dir_all(t.data_path(&format!("uploads/{}", new_uuid()))).unwrap();
    std::fs::remove_file(t.blob_path(&done)).unwrap();
    let report = keeman_server::jobs::check_attachments(&t.app)
        .await
        .unwrap();
    assert_eq!(
        report,
        keeman_server::jobs::AttachmentReport {
            leftover_uploads: 1,
            orphaned_files: 1,
            missing_files: 1,
        }
    );
    assert!(t.blob_path(&stray).exists());
}
