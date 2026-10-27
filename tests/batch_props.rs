//! Property tests of the batch semantics: two clients with possibly
//! stale views send random batches; the server must behave exactly like a
//! simple model, so no update is ever lost. Once the manifest root exists,
//! a batch without it is refused.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::http::StatusCode;
use keeman_server::manifest_ids::root_id;
use proptest::prelude::*;
use proptest::test_runner::{Config, TestCaseError, TestRunner};
use serde_json::{Value, json};
use support::{Account, Req, TestApp, envelope, new_uuid};

const KINDS: [&str; 3] = ["group", "entry", "icon"];

#[derive(Debug, Clone)]
enum Action {
    /// A batch of a client: new objects and changes to objects it knows.
    Batch { client: usize, ops: Vec<OpChoice> },
    /// A client syncs with the given page size.
    Sync { client: usize, limit: usize },
    /// The last batch is sent again with the same key and body.
    Repeat,
}

#[derive(Debug, Clone)]
enum OpChoice {
    Create(usize),
    Update(usize),
    Delete(usize),
    /// Writes the manifest root (creates it if the client has not seen it).
    Root,
}

fn action() -> impl Strategy<Value = Action> {
    let op = prop_oneof![
        (0..KINDS.len()).prop_map(OpChoice::Create),
        any::<usize>().prop_map(OpChoice::Update),
        any::<usize>().prop_map(OpChoice::Delete),
        Just(OpChoice::Root),
    ];
    prop_oneof![
        4 => (0..2usize, prop::collection::vec(op, 1..5))
            .prop_map(|(client, ops)| Action::Batch { client, ops }),
        2 => (0..2usize, prop_oneof![Just(1usize), Just(2), Just(3), Just(500)])
            .prop_map(|(client, limit)| Action::Sync { client, limit }),
        1 => Just(Action::Repeat),
    ]
}

#[derive(Debug, Clone, PartialEq)]
struct Stored {
    kind: String,
    revision: i64,
    deleted: bool,
    data: String,
}

/// What the server should hold.
#[derive(Default)]
struct Model {
    revision: i64,
    objects: BTreeMap<String, Stored>,
}

/// What a client saw at its last sync.
#[derive(Default, Clone)]
struct View {
    since: i64,
    objects: BTreeMap<String, Stored>,
}

impl Model {
    /// Once the root exists, a batch without a put on it is refused.
    fn requires_root(&self, ops: &[Value], root: &str) -> bool {
        self.objects.get(root).is_some_and(|s| !s.deleted)
            && !ops.iter().any(|op| op["op"] == "put" && op["id"] == root)
    }

    /// The expected conflict list; empty means the batch applies.
    fn conflicts(&self, ops: &[Value]) -> Vec<Value> {
        ops.iter()
            .filter_map(|op| {
                let id = op["id"].as_str().unwrap();
                let stored = self.objects.get(id);
                let expected = op["expected_revision"].as_i64();
                let entry = |revision: Option<i64>, deleted: bool| {
                    Some(json!({ "id": id, "current_revision": revision, "deleted": deleted }))
                };
                match (expected, stored) {
                    (None, None) => None,
                    (None, Some(s)) => entry(Some(s.revision), s.deleted),
                    (Some(_), None) => entry(None, false),
                    (Some(_), Some(s)) if s.deleted => entry(Some(s.revision), true),
                    (Some(e), Some(s)) if s.revision != e => entry(Some(s.revision), false),
                    _ => None,
                }
            })
            .collect()
    }

    fn apply(&mut self, ops: &[Value]) {
        self.revision += 1;
        for op in ops {
            let id = op["id"].as_str().unwrap().to_string();
            let kind = match op["type"].as_str() {
                Some(kind) => kind.to_string(),
                None => self.objects[&id].kind.clone(),
            };
            self.objects.insert(
                id,
                Stored {
                    kind,
                    revision: self.revision,
                    deleted: op["op"] == "delete",
                    data: op["data"].as_str().unwrap().to_string(),
                },
            );
        }
    }
}

fn build_ops(view: &View, root: &str, choices: &[OpChoice]) -> Vec<Value> {
    // `vault_meta` and the manifest cannot be deleted (a structural 400), so
    // they are left out; the root has its own choice.
    let known: Vec<(&String, &Stored)> = view
        .objects
        .iter()
        .filter(|(_, s)| !s.deleted && s.kind != "vault_meta" && s.kind != "manifest")
        .collect();
    let mut used = std::collections::HashSet::new();
    let mut ops = Vec::new();
    for choice in choices {
        match choice {
            OpChoice::Root => {
                if used.insert(root.to_string()) {
                    ops.push(json!({
                        "op": "put", "id": root, "type": "manifest", "key_version": 1,
                        "expected_revision": view.objects.get(root).map(|s| s.revision),
                        "data": envelope(60),
                    }));
                }
            }
            OpChoice::Create(kind) => ops.push(json!({
                "op": "put", "id": new_uuid(), "type": KINDS[*kind], "key_version": 1,
                "expected_revision": null, "data": envelope(60),
            })),
            OpChoice::Update(pick) | OpChoice::Delete(pick) if !known.is_empty() => {
                let (id, stored) = known[pick % known.len()];
                if !used.insert(id.clone()) {
                    continue;
                }
                ops.push(if matches!(choice, OpChoice::Update(_)) {
                    json!({
                        "op": "put", "id": id, "type": stored.kind, "key_version": 1,
                        "expected_revision": stored.revision, "data": envelope(60),
                    })
                } else {
                    json!({
                        "op": "delete", "id": id, "key_version": 1,
                        "expected_revision": stored.revision, "data": envelope(50),
                    })
                });
            }
            _ => {}
        }
    }
    ops
}

async fn sync(
    t: &TestApp,
    account: &Account,
    vault_id: &str,
    since: i64,
    limit: usize,
) -> (BTreeMap<String, Stored>, i64) {
    let mut objects = BTreeMap::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut query = format!("since={since}&limit={limit}");
        if let Some(c) = &cursor {
            query.push_str(&format!("&cursor={c}"));
        }
        let response = t.changes(account, vault_id, &query).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        let page = response.json();
        for o in page["objects"].as_array().unwrap() {
            objects.insert(
                o["id"].as_str().unwrap().to_string(),
                Stored {
                    kind: o["type"].as_str().unwrap().to_string(),
                    revision: o["revision"].as_i64().unwrap(),
                    deleted: o["deleted"].as_bool().unwrap(),
                    data: o["data"].as_str().unwrap().to_string(),
                },
            );
        }
        match page["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => return (objects, page["vault_revision"].as_i64().unwrap()),
        }
    }
}

/// Batches applied and rejected with conflicts, over all cases.
static APPLIED: AtomicUsize = AtomicUsize::new(0);
static CONFLICTED: AtomicUsize = AtomicUsize::new(0);
static REQUIRED: AtomicUsize = AtomicUsize::new(0);

async fn run_case(
    t: &TestApp,
    clients: &[Account; 2],
    actions: Vec<Action>,
) -> Result<(), TestCaseError> {
    let vault_id = t.create_vault(&clients[0]).await;
    t.add_member(&vault_id, &clients[1], "member", "active")
        .await;
    let path = format!("/v1/vaults/{vault_id}/batch");
    let root = root_id(&vault_id);
    let (initial, revision) = sync(t, &clients[0], &vault_id, 0, 500).await;
    let mut model = Model {
        revision,
        objects: initial.clone(),
    };
    let start = View {
        since: revision,
        objects: initial,
    };
    let mut views = [start.clone(), start];
    let mut last: Option<(usize, String, Value, StatusCode, Vec<u8>)> = None;

    for action in actions {
        match action {
            Action::Batch { client, ops } => {
                let ops = build_ops(&views[client], &root, &ops);
                if ops.is_empty() {
                    continue;
                }
                let key = new_uuid();
                let body = json!({ "ops": ops });
                let response = t
                    .call(
                        Req::post(&path)
                            .token(&clients[client].access_token)
                            .idem(&key)
                            .json(&body),
                    )
                    .await;
                let conflicts = model.conflicts(&ops);
                if model.requires_root(&ops, &root) {
                    prop_assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
                    prop_assert_eq!(response.code(), "manifest_required");
                    REQUIRED.fetch_add(1, Ordering::Relaxed);
                } else if conflicts.is_empty() {
                    prop_assert_eq!(response.status, StatusCode::OK, "{}", response.text());
                    model.apply(&ops);
                    APPLIED.fetch_add(1, Ordering::Relaxed);
                    prop_assert_eq!(&response.json()["vault_revision"], &json!(model.revision));
                } else {
                    prop_assert_eq!(response.status, StatusCode::CONFLICT);
                    prop_assert_eq!(&response.json()["conflicts"], &json!(conflicts));
                    CONFLICTED.fetch_add(1, Ordering::Relaxed);
                }
                last = Some((client, key, body, response.status, response.body.to_vec()));
            }
            Action::Sync { client, limit } => {
                let view = &mut views[client];
                let (delta, revision) =
                    sync(t, &clients[client], &vault_id, view.since, limit).await;
                for (id, stored) in delta {
                    view.objects.insert(id, stored);
                }
                view.since = revision;
                // A client that synced holds exactly the model.
                prop_assert_eq!(&view.objects, &model.objects);
            }
            Action::Repeat => {
                let Some((client, key, body, status, bytes)) = &last else {
                    continue;
                };
                let response = t
                    .call(
                        Req::post(&path)
                            .token(&clients[*client].access_token)
                            .idem(key)
                            .json(body),
                    )
                    .await;
                prop_assert_eq!(response.status, *status);
                if status.is_success() {
                    prop_assert_eq!(&response.body.to_vec(), bytes);
                } else {
                    prop_assert_eq!(
                        &response.json()["conflicts"],
                        &serde_json::from_slice::<Value>(bytes).unwrap()["conflicts"]
                    );
                }
            }
        }
    }

    // The full state with any page size equals the live objects of the model.
    for limit in [1, 7, 1000] {
        let (full, revision) = sync(t, &clients[1], &vault_id, 0, limit).await;
        prop_assert_eq!(revision, model.revision);
        let live: BTreeMap<String, Stored> = model
            .objects
            .iter()
            .filter(|(_, s)| !s.deleted)
            .map(|(id, s)| (id.clone(), s.clone()))
            .collect();
        prop_assert_eq!(&full, &live);
    }
    Ok(())
}

#[test]
fn batches_behave_like_the_model() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (t, clients) = runtime.block_on(async {
        // Every case uses the same sessions; the per-session limit would bite.
        let t = TestApp::with_config(
            "[rate_limits]\nsession_per_min = 1000000\naccount_per_min = 1000000\n",
        )
        .await;
        let alice = t.register("alice@example.com").await;
        let bob = t.register("bob@example.com").await;
        (t, [alice, bob])
    });
    let mut runner = TestRunner::new(Config {
        cases: 128,
        ..Config::default()
    });
    runner
        .run(&prop::collection::vec(action(), 1..30), |actions| {
            runtime.block_on(run_case(&t, &clients, actions))
        })
        .unwrap();
    assert!(APPLIED.load(Ordering::Relaxed) > 100);
    assert!(
        CONFLICTED.load(Ordering::Relaxed) > 20,
        "stale views must conflict"
    );
    assert!(
        REQUIRED.load(Ordering::Relaxed) > 20,
        "batches without the root must be refused"
    );
}
