//! Verifies that the migration loader picks up both 0001 and 0002 and that the
//! new permissions / peer_create_allowed tables exist with the expected PK
//! constraints.

use rusqlite::Connection;

const M0001: &str = include_str!("../src/db/migrations/0001_initial.sql");
const M0002: &str = include_str!("../src/db/migrations/0002_permissions.sql");

fn fresh() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    c.pragma_update(None, "foreign_keys", "ON").unwrap();
    c.execute_batch(M0001).unwrap();
    c.execute_batch(M0002).unwrap();
    c
}

#[tokio::test]
async fn store_in_memory_applies_both_migrations() {
    // The library-level `Store::in_memory()` is the production code path; it
    // must succeed with the new 0002 included.
    let s = terminal_hub_server::db::Store::in_memory().unwrap();
    // Touch a couple of API methods that depend on M3 tables to confirm nothing
    // regressed.
    assert!(s.get_user("nobody@x").await.unwrap().is_none());
}

#[test]
fn migrations_create_permissions_tables() {
    let c = fresh();
    let mut stmt = c
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap();
    let names: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert!(
        names.iter().any(|n| n == "permissions"),
        "permissions missing: {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "peer_create_allowed"),
        "peer_create_allowed missing: {names:?}"
    );
    // M3 tables should still be present.
    assert!(names.iter().any(|n| n == "users"), "tables: {names:?}");
    assert!(names.iter().any(|n| n == "audit_log"), "tables: {names:?}");
}

#[test]
fn audit_log_has_peer_and_session_columns() {
    let c = fresh();
    let mut stmt = c.prepare("PRAGMA table_info(audit_log)").unwrap();
    let cols: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert!(cols.iter().any(|c| c == "peer_id"), "cols: {cols:?}");
    assert!(cols.iter().any(|c| c == "session_id"), "cols: {cols:?}");
}

#[test]
fn permissions_pk_rejects_duplicate_tuple() {
    let c = fresh();
    c.execute(
        "INSERT INTO users(email, pubkey_openssh, role, enrolled_at) VALUES (?1, 'ssh', 'primary', 0)",
        ["a@x"],
    )
    .unwrap();
    c.execute(
        "INSERT INTO users(email, pubkey_openssh, role, enrolled_at) VALUES (?1, 'ssh', 'secondary', 0)",
        ["b@x"],
    )
    .unwrap();
    c.execute(
        "INSERT INTO permissions(user_email, peer_id, session_id, capabilities, granted_by, granted_at)
         VALUES ('b@x', 'local', 's1', 1, 'a@x', 0)",
        [],
    )
    .unwrap();
    let err = c.execute(
        "INSERT INTO permissions(user_email, peer_id, session_id, capabilities, granted_by, granted_at)
         VALUES ('b@x', 'local', 's1', 7, 'a@x', 0)",
        [],
    );
    assert!(err.is_err(), "duplicate (user,peer,session) must violate PK");
}

#[test]
fn cascade_delete_user_removes_permissions() {
    let c = fresh();
    c.execute(
        "INSERT INTO users(email, pubkey_openssh, role, enrolled_at) VALUES ('p@x','ssh','primary',0)",
        [],
    )
    .unwrap();
    c.execute(
        "INSERT INTO users(email, pubkey_openssh, role, enrolled_at) VALUES ('s@x','ssh','secondary',0)",
        [],
    )
    .unwrap();
    c.execute(
        "INSERT INTO permissions(user_email,peer_id,session_id,capabilities,granted_by,granted_at)
         VALUES ('s@x','local','sess1',7,'p@x',0)",
        [],
    )
    .unwrap();
    c.execute("DELETE FROM users WHERE email='s@x'", []).unwrap();
    let n: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM permissions WHERE user_email='s@x'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 0, "FK cascade should delete permission rows");
}
