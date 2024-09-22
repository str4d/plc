use std::collections::HashMap;

use anyhow::anyhow;
use async_sqlite::{
    rusqlite::{
        named_params, CachedStatement, Connection, OpenFlags, OptionalExtension, Row, Transaction,
    },
    JournalMode, Pool, PoolBuilder,
};
use atrium_api::types::string::{Cid, Datetime, Did};
use tracing::info;

use crate::{
    data::{PlcData, ATPROTO_PDS_KIND, ATPROTO_PDS_TYPE, ATPROTO_VERIFICATION_METHOD},
    remote::plc,
};

use super::ExportParams;

#[derive(Clone)]
pub(crate) struct Db {
    inner: Pool,
}

impl Db {
    pub(crate) async fn open(path: &str, read_only: bool) -> anyhow::Result<Self> {
        let inner = PoolBuilder::new()
            .path(path)
            .flags(if read_only {
                OpenFlags::SQLITE_OPEN_READ_ONLY
                    | OpenFlags::SQLITE_OPEN_URI
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX
            } else {
                OpenFlags::default()
            })
            .journal_mode(JournalMode::Wal)
            .open()
            .await?;

        if !read_only {
            // Ensure the necessary tables exist.
            inner
                .conn_mut(|conn| {
                    let tx = conn.transaction()?;
                    tx.execute_batch(CREATE_DATABASES)?;
                    tx.commit()
                })
                .await?;
        }

        Ok(Self { inner })
    }

    pub(crate) async fn close(self) -> anyhow::Result<()> {
        Ok(self.inner.close().await?)
    }

    pub(crate) async fn get_last_created(&self) -> anyhow::Result<Option<Datetime>> {
        let created_at = self
            .inner
            .conn(|conn| {
                conn.query_row(
                    "SELECT created_at
                    FROM plc_log
                    ORDER BY created_at DESC
                    LIMIT 1",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .optional()
            })
            .await?;

        Ok(created_at.map(|s| s.parse()).transpose()?)
    }

    pub(crate) async fn import(
        &self,
        entries: Vec<plc::LogEntry>,
    ) -> anyhow::Result<Option<(Datetime, usize)>> {
        info!("Importing {} entries", entries.len());

        Ok(self
            .inner
            .conn_mut(|conn| {
                let mut latest_created_at = None;
                let imported = entries.len();

                let tx = conn.transaction()?;

                {
                    let mut db = DbInserter::new(&tx)?;

                    for entry in entries {
                        let identity_id = db.insert_did(entry.did)?;

                        match entry.operation.content {
                            plc::Operation::Change(op) => {
                                let atproto_signing = op
                                    .data
                                    .verification_methods
                                    .iter()
                                    .find(|(method, _)| *method == ATPROTO_VERIFICATION_METHOD)
                                    .map(|(_, key)| db.insert_key(key))
                                    .transpose()?;

                                let atproto_pds = op
                                    .data
                                    .services
                                    .iter()
                                    .find(|(kind, service)| {
                                        // A couple of DIDs exist that use `atproto_pds`
                                        // with `atprotoPersonalDataServer` instead of the
                                        // correct capitalization. We have to leave these
                                        // stored in `verification_methods` in order for
                                        // the operation to be canonically readable.
                                        *kind == ATPROTO_PDS_KIND
                                            && service.r#type == ATPROTO_PDS_TYPE
                                    })
                                    .map(|(_, service)| db.insert_atproto_pds(&service.endpoint))
                                    .transpose()?;

                                let entry_id = db.insert_entry(
                                    entry.cid,
                                    identity_id,
                                    entry.created_at.as_str(),
                                    entry.nullified,
                                    "O",
                                    Some(op.data.also_known_as),
                                    atproto_signing,
                                    atproto_pds,
                                    op.prev,
                                    &entry.operation.sig,
                                )?;

                                for (authority, key) in op.data.rotation_keys.iter().enumerate() {
                                    db.insert_rotation_key(entry_id, authority, key)?;
                                }

                                for (service, key) in
                                    op.data.verification_methods.into_iter().filter(
                                        |(method, _)| *method != ATPROTO_VERIFICATION_METHOD,
                                    )
                                {
                                    db.insert_verification_method(entry_id, &service, &key)?;
                                }

                                for (kind, service) in
                                    op.data.services.into_iter().filter(|(kind, service)| {
                                        !(*kind == ATPROTO_PDS_KIND
                                            && service.r#type == ATPROTO_PDS_TYPE)
                                    })
                                {
                                    db.insert_service(
                                        entry_id,
                                        &kind,
                                        &service.r#type,
                                        &service.endpoint,
                                    )?;
                                }
                            }
                            plc::Operation::Tombstone(op) => {
                                db.insert_entry(
                                    entry.cid,
                                    identity_id,
                                    entry.created_at.as_str(),
                                    entry.nullified,
                                    "T",
                                    None,
                                    None,
                                    None,
                                    Some(op.prev),
                                    &entry.operation.sig,
                                )?;
                            }
                            plc::Operation::LegacyCreate(op) => {
                                let atproto_signing = db.insert_key(&op.signing_key)?;
                                let atproto_pds = db.insert_atproto_pds(&op.service)?;

                                let entry_id = db.insert_entry(
                                    entry.cid,
                                    identity_id,
                                    entry.created_at.as_str(),
                                    entry.nullified,
                                    "C",
                                    Some(vec![format!("at://{}", op.handle)]),
                                    Some(atproto_signing),
                                    Some(atproto_pds),
                                    None,
                                    &entry.operation.sig,
                                )?;

                                db.insert_rotation_key(entry_id, 0, &op.recovery_key)?;
                                db.insert_rotation_key(entry_id, 1, &op.signing_key)?;
                            }
                        }

                        latest_created_at = Some(entry.created_at);
                    }
                }

                tx.commit()?;

                if let Some(latest_created_at) = latest_created_at {
                    Ok(Some((latest_created_at, imported)))
                } else {
                    assert_eq!(imported, 0);
                    Ok(None)
                }
            })
            .await?)
    }

    pub(crate) async fn total_dids(&self) -> anyhow::Result<u64> {
        let total_dids = self
            .inner
            .conn(move |conn| {
                conn.prepare(
                    "SELECT identity_id
                    FROM identity
                    ORDER BY identity_id DESC
                    LIMIT 1",
                )?
                .query_row([], |row| row.get("identity_id"))
            })
            .await?;

        Ok(total_dids)
    }

    pub(crate) async fn list_dids(
        &self,
        count: usize,
        after: Option<u64>,
    ) -> anyhow::Result<Vec<(u64, Did)>> {
        let dids = self
            .inner
            .conn(move |conn| {
                conn.prepare(
                    "SELECT identity_id, did
                    FROM identity
                    ORDER BY identity_id
                    LIMIT :count
                    OFFSET :offset",
                )?
                .query_map(
                    named_params! {":count": count, ":offset": after.unwrap_or(0)},
                    |row| Ok((row.get("identity_id")?, row.get("did")?)),
                )?
                .collect::<Result<Vec<_>, _>>()
            })
            .await?;

        dids.into_iter()
            .map(|(id, did)| {
                Did::new(did)
                    .map_err(|e| anyhow!("{e}"))
                    .map(|did| (id, did))
            })
            .collect()
    }

    pub(crate) async fn get_last_active_entry(
        &self,
        did: Did,
    ) -> anyhow::Result<Option<plc::LogEntry>> {
        let entry = self
            .inner
            .conn(|conn| match Entry::get_latest_active(conn, did)? {
                None => Ok(None),
                Some(entry) => entry.hydrate(conn).map(Some),
            })
            .await?;

        entry.map(|entry| entry.assemble()).transpose()
    }

    pub(crate) async fn get_audit_log(&self, did: Did) -> anyhow::Result<Vec<plc::LogEntry>> {
        let entries = self
            .inner
            .conn(|conn| {
                Entry::get_audit_log(conn, did)?
                    .into_iter()
                    .map(|entry| entry.hydrate(conn))
                    .collect::<Result<Vec<_>, _>>()
            })
            .await?;

        entries.into_iter().map(|entry| entry.assemble()).collect()
    }

    pub(crate) async fn export(&self, params: ExportParams) -> anyhow::Result<Vec<plc::LogEntry>> {
        let entries = self
            .inner
            .conn(|conn| {
                Entry::get_log_entries(conn, params.bounded_count(), params.after)?
                    .into_iter()
                    .map(|entry| entry.hydrate(conn))
                    .collect::<Result<Vec<_>, _>>()
            })
            .await?;

        entries.into_iter().map(|entry| entry.assemble()).collect()
    }
}

const CREATE_DATABASES: &str = "
CREATE TABLE IF NOT EXISTS identity (
    identity_id INTEGER PRIMARY KEY,
    did TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS key (
    key_id INTEGER PRIMARY KEY,
    key TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS atproto_pds (
    pds_id INTEGER PRIMARY KEY,
    endpoint TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS plc_log (
    entry_id INTEGER PRIMARY KEY,
    cid BLOB NOT NULL UNIQUE,
    identity INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    nullified INTEGER,
    -- operation
    type TEXT NOT NULL CHECK(type IN ('O','T','C')),
    also_known_as JSON,
    atproto_signing INTEGER,
    atproto_pds INTEGER,
    prev INTEGER,
    -- Signatures are stored in their Base64 encoding because
    -- the log contains signatures with invalid padding.
    sig TEXT NOT NULL,
    FOREIGN KEY(identity) REFERENCES identity(identity_id),
    FOREIGN KEY(atproto_signing) REFERENCES key(key_id)
    FOREIGN KEY(atproto_pds) REFERENCES atproto_pds(pds_id)
    FOREIGN KEY(prev) REFERENCES plc_log(entry_id)
);
CREATE INDEX IF NOT EXISTS plc_log_idx_created_at ON plc_log(created_at DESC);
CREATE INDEX IF NOT EXISTS plc_log_idx_identity_created_at ON plc_log(identity, created_at);
CREATE TABLE IF NOT EXISTS rotation_keys (
    entry INTEGER NOT NULL,
    authority INTEGER NOT NULL,
    key INTEGER NOT NULL,
    FOREIGN KEY(entry) REFERENCES plc_log(entry_id),
    FOREIGN KEY(key) REFERENCES key(key_id)
    CONSTRAINT rotation_keys_set UNIQUE(entry, authority)
);
CREATE INDEX IF NOT EXISTS rotation_keys_idx_entry_key ON rotation_keys(entry, key);
CREATE TABLE IF NOT EXISTS verification_methods (
    entry INTEGER NOT NULL,
    service TEXT NOT NULL,
    key INTEGER NOT NULL,
    FOREIGN KEY(entry) REFERENCES plc_log(entry_id),
    FOREIGN KEY(key) REFERENCES key(key_id),
    CONSTRAINT verification_methods_map UNIQUE(entry, service)
);
CREATE INDEX IF NOT EXISTS verification_methods_idx_entry_key ON verification_methods(entry, key);
CREATE TABLE IF NOT EXISTS services (
    entry INTEGER NOT NULL,
    kind TEXT NOT NULL,
    type TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    FOREIGN KEY(entry) REFERENCES plc_log(entry_id),
    CONSTRAINT services_map UNIQUE(entry, kind)
);";

struct DbInserter<'a> {
    stmt_find_entry: CachedStatement<'a>,
    stmt_insert_did: CachedStatement<'a>,
    stmt_insert_key: CachedStatement<'a>,
    stmt_insert_atproto_pds: CachedStatement<'a>,
    stmt_insert_entry: CachedStatement<'a>,
    stmt_insert_rotation_key: CachedStatement<'a>,
    stmt_insert_verification_method: CachedStatement<'a>,
    stmt_insert_service: CachedStatement<'a>,
}

impl<'a> DbInserter<'a> {
    fn new(tx: &'a Transaction) -> async_sqlite::rusqlite::Result<Self> {
        let stmt_find_entry = tx.prepare_cached(
            "SELECT entry_id
            FROM plc_log
            WHERE cid = :cid",
        )?;

        let stmt_insert_did = tx.prepare_cached(
            "INSERT INTO identity(did) VALUES(:did)
            ON CONFLICT DO UPDATE SET did = did
            RETURNING identity_id",
        )?;

        let stmt_insert_key = tx.prepare_cached(
            "INSERT INTO key(key) VALUES(:key)
            ON CONFLICT DO UPDATE SET key = key
            RETURNING key_id",
        )?;

        let stmt_insert_atproto_pds = tx.prepare_cached(
            "INSERT INTO atproto_pds(endpoint) VALUES(:endpoint)
            ON CONFLICT DO UPDATE SET endpoint = endpoint
            RETURNING pds_id",
        )?;

        let stmt_insert_entry = tx.prepare_cached(
            "INSERT INTO plc_log(
                cid, identity, created_at, nullified,
                type, also_known_as, atproto_signing, atproto_pds, prev, sig
            ) VALUES(
                :cid, :identity, :created_at, :nullified,
                :type, :also_known_as, :atproto_signing, :atproto_pds, :prev, :sig
            )
            ON CONFLICT(cid) DO UPDATE SET cid = cid
            RETURNING entry_id",
        )?;

        let stmt_insert_rotation_key = tx.prepare_cached(
            "INSERT INTO rotation_keys(entry, authority, key)
            VALUES(:entry, :authority, :key)
            ON CONFLICT DO NOTHING",
        )?;

        let stmt_insert_verification_method = tx.prepare_cached(
            "INSERT INTO verification_methods(entry, service, key)
            VALUES(:entry, :service, :key)
            ON CONFLICT DO NOTHING",
        )?;

        let stmt_insert_service = tx.prepare_cached(
            "INSERT INTO services(entry, kind, type, endpoint)
            VALUES(:entry, :kind, :type, :endpoint)
            ON CONFLICT DO NOTHING",
        )?;

        Ok(Self {
            stmt_find_entry,
            stmt_insert_did,
            stmt_insert_key,
            stmt_insert_atproto_pds,
            stmt_insert_entry,
            stmt_insert_rotation_key,
            stmt_insert_verification_method,
            stmt_insert_service,
        })
    }

    fn insert_did(&mut self, did: Did) -> async_sqlite::rusqlite::Result<i64> {
        self.stmt_insert_did
            .query_row(named_params! {":did": did.as_ref()}, |row| row.get(0))
    }

    fn insert_key(&mut self, key: &str) -> async_sqlite::rusqlite::Result<i64> {
        self.stmt_insert_key
            .query_row(named_params! {":key": key}, |row| row.get(0))
    }

    fn insert_atproto_pds(&mut self, endpoint: &str) -> async_sqlite::rusqlite::Result<i64> {
        self.stmt_insert_atproto_pds
            .query_row(named_params! {":endpoint": endpoint}, |row| row.get(0))
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_entry(
        &mut self,
        cid: Cid,
        identity_id: i64,
        created_at: &str,
        nullified: bool,
        r#type: &str,
        also_known_as: Option<Vec<String>>,
        atproto_signing: Option<i64>,
        atproto_pds: Option<i64>,
        prev: Option<Cid>,
        sig: &str,
    ) -> async_sqlite::rusqlite::Result<i64> {
        let also_known_as = also_known_as.map(|aka| {
            serde_json::Value::Array(aka.into_iter().map(serde_json::Value::String).collect())
        });

        let prev = prev
            .map(|cid| {
                self.stmt_find_entry
                    .query_row(named_params! {":cid": cid.as_ref().to_bytes()}, |row| {
                        row.get::<_, i64>(0)
                    })
            })
            .transpose()?;

        self.stmt_insert_entry.query_row(
            named_params! {
                ":cid": cid.as_ref().to_bytes(),
                ":identity": identity_id,
                ":created_at": created_at,
                ":nullified": nullified,
                ":type": r#type,
                ":also_known_as": also_known_as,
                ":atproto_signing": atproto_signing,
                ":atproto_pds": atproto_pds,
                ":prev": prev,
                ":sig": sig,
            },
            |row| row.get(0),
        )
    }

    fn insert_rotation_key(
        &mut self,
        entry_id: i64,
        authority: usize,
        key: &str,
    ) -> async_sqlite::rusqlite::Result<()> {
        let key_id = self.insert_key(key)?;
        self.stmt_insert_rotation_key.execute(named_params! {
            ":entry": entry_id,
            ":authority": authority,
            ":key": key_id,
        })?;
        Ok(())
    }

    fn insert_verification_method(
        &mut self,
        entry_id: i64,
        service: &str,
        key: &str,
    ) -> async_sqlite::rusqlite::Result<()> {
        let key_id = self.insert_key(key)?;
        self.stmt_insert_verification_method
            .execute(named_params! {
                ":entry": entry_id,
                ":service": service,
                ":key": key_id,
            })?;
        Ok(())
    }

    fn insert_service(
        &mut self,
        entry_id: i64,
        kind: &str,
        r#type: &str,
        endpoint: &str,
    ) -> async_sqlite::rusqlite::Result<()> {
        self.stmt_insert_service.execute(named_params! {
            ":entry": entry_id,
            ":kind": kind,
            ":type": r#type,
            ":endpoint": endpoint,
        })?;
        Ok(())
    }
}

#[derive(Debug)]
struct Entry {
    entry_id: i64,
    did: Result<Did, &'static str>,
    cid: cid::Result<cid::Cid>,
    created_at: Result<Datetime, chrono::ParseError>,
    nullified: bool,
    r#type: String,
    also_known_as: Option<serde_json::Value>,
    atproto_signing: Option<String>,
    atproto_pds: Option<String>,
    prev: Option<cid::Result<cid::Cid>>,
    sig: String,
}

impl Entry {
    fn get_latest_active(
        conn: &Connection,
        did: Did,
    ) -> async_sqlite::rusqlite::Result<Option<Self>> {
        conn.query_row(
            "SELECT
                curr.entry_id,
                curr.cid,
                curr.created_at,
                curr.nullified,
                curr.type,
                curr.also_known_as,
                signing.key AS atproto_signing,
                atproto_pds.endpoint AS atproto_pds,
                prev.cid AS prev,
                curr.sig
            FROM plc_log curr
            JOIN identity ON curr.identity = identity.identity_id
            LEFT JOIN key signing ON curr.atproto_signing = signing.key_id
            LEFT JOIN atproto_pds ON curr.atproto_pds = atproto_pds.pds_id
            LEFT JOIN plc_log prev ON curr.prev = prev.entry_id
            WHERE did = :did
            AND curr.nullified IS FALSE
            ORDER BY curr.created_at DESC
            LIMIT 1",
            named_params! {":did": did.clone().as_ref()},
            |row| Self::from_row(Ok(did), row),
        )
        .optional()
    }

    fn get_audit_log(conn: &Connection, did: Did) -> async_sqlite::rusqlite::Result<Vec<Self>> {
        conn.prepare(
            "SELECT
                curr.entry_id,
                curr.cid,
                curr.created_at,
                curr.nullified,
                curr.type,
                curr.also_known_as,
                signing.key AS atproto_signing,
                atproto_pds.endpoint AS atproto_pds,
                prev.cid AS prev,
                curr.sig
            FROM plc_log curr
            JOIN identity ON curr.identity = identity.identity_id
            LEFT JOIN key signing ON curr.atproto_signing = signing.key_id
            LEFT JOIN atproto_pds ON curr.atproto_pds = atproto_pds.pds_id
            LEFT JOIN plc_log prev ON curr.prev = prev.entry_id
            WHERE did = :did
            ORDER BY curr.created_at",
        )?
        .query_map(named_params! {":did": did.clone().as_ref()}, |row| {
            Self::from_row(Ok(did.clone()), row)
        })?
        .collect()
    }

    fn get_log_entries(
        conn: &Connection,
        count: usize,
        after: Option<Datetime>,
    ) -> async_sqlite::rusqlite::Result<Vec<Self>> {
        conn.prepare(
            "SELECT
                curr.entry_id,
                identity.did,
                curr.cid,
                curr.created_at,
                curr.nullified,
                curr.type,
                curr.also_known_as,
                signing.key AS atproto_signing,
                atproto_pds.endpoint AS atproto_pds,
                prev.cid AS prev,
                curr.sig
            FROM plc_log curr
            JOIN identity ON curr.identity = identity.identity_id
            LEFT JOIN key signing ON curr.atproto_signing = signing.key_id
            LEFT JOIN atproto_pds ON curr.atproto_pds = atproto_pds.pds_id
            LEFT JOIN plc_log prev ON curr.prev = prev.entry_id
            WHERE curr.created_at > :after
            ORDER BY curr.created_at
            LIMIT :count",
        )?
        .query_map(
            named_params! {":after": after.as_ref().map(|d| d.as_str()), ":count": count},
            |row| Self::from_row(Did::new(row.get("did")?), row),
        )?
        .collect()
    }

    fn from_row(did: Result<Did, &'static str>, row: &Row) -> async_sqlite::rusqlite::Result<Self> {
        Ok(Self {
            entry_id: row.get("entry_id")?,
            did,
            cid: cid::Cid::read_bytes(row.get_ref("cid")?.as_blob()?),
            created_at: row.get_ref("created_at")?.as_str()?.parse(),
            nullified: row.get("nullified")?,
            r#type: row.get("type")?,
            also_known_as: row.get("also_known_as")?,
            atproto_signing: row.get("atproto_signing")?,
            atproto_pds: row.get("atproto_pds")?,
            prev: row
                .get_ref("prev")?
                .as_blob_or_null()?
                .map(cid::Cid::read_bytes),
            sig: row.get("sig")?,
        })
    }

    fn hydrate(self, conn: &Connection) -> async_sqlite::rusqlite::Result<HydratedEntry> {
        let rotation_keys = conn
            .prepare(
                "SELECT key.key
            FROM rotation_keys r
            JOIN key ON r.key = key.key_id
            WHERE entry = :entry
            ORDER BY authority",
            )?
            .query_map(named_params! {":entry": self.entry_id}, |row| {
                row.get::<_, String>("key")
            })?
            .collect::<Result<_, _>>()?;

        let verification_methods = conn
            .prepare(
                "SELECT service, key.key
            FROM verification_methods v
            JOIN key ON v.key = key.key_id
            WHERE entry = :entry",
            )?
            .query_map(named_params! {":entry": self.entry_id}, |row| {
                Ok((row.get("service")?, row.get("key")?))
            })?
            .collect::<Result<_, _>>()?;

        let services = conn
            .prepare(
                "SELECT kind, type, endpoint
            FROM services
            WHERE entry = :entry",
            )?
            .query_map(named_params! {":entry": self.entry_id}, |row| {
                Ok((row.get("kind")?, (row.get("type")?, row.get("endpoint")?)))
            })?
            .collect::<Result<_, _>>()?;

        Ok(HydratedEntry {
            entry: self,
            rotation_keys,
            verification_methods,
            services,
        })
    }
}

struct HydratedEntry {
    entry: Entry,
    rotation_keys: Vec<String>,
    verification_methods: HashMap<String, String>,
    services: HashMap<String, (String, String)>,
}

impl HydratedEntry {
    fn assemble(self) -> anyhow::Result<plc::LogEntry> {
        let Self {
            entry,
            rotation_keys,
            mut verification_methods,
            services,
        } = self;

        let cid = Cid::new(entry.cid?);
        let prev = entry.prev.transpose()?.map(Cid::new);

        let content = match entry.r#type.as_str() {
            "O" => {
                let also_known_as = match entry
                    .also_known_as
                    .ok_or_else(|| anyhow!("Missing also_known_as"))?
                {
                    serde_json::Value::Array(v) => v
                        .into_iter()
                        .map(|e| match e {
                            serde_json::Value::String(s) => Ok(s),
                            _ => Err(anyhow!("also_known_as does not contain strings")),
                        })
                        .collect(),
                    _ => Err(anyhow!("also_known_as is not an array")),
                }?;

                if let Some(endpoint) = entry.atproto_signing {
                    verification_methods.insert(ATPROTO_VERIFICATION_METHOD.into(), endpoint);
                }

                let services = services
                    .into_iter()
                    .map(|(kind, (r#type, endpoint))| {
                        (kind, crate::data::Service { r#type, endpoint })
                    })
                    .chain(entry.atproto_pds.map(|endpoint| {
                        (
                            ATPROTO_PDS_KIND.into(),
                            crate::data::Service {
                                r#type: ATPROTO_PDS_TYPE.into(),
                                endpoint,
                            },
                        )
                    }))
                    .collect();

                Ok(plc::Operation::Change(plc::ChangeOp {
                    data: PlcData {
                        rotation_keys,
                        verification_methods,
                        also_known_as,
                        services,
                    },
                    prev,
                }))
            }
            "T" => {
                if entry.also_known_as.is_some()
                    || entry.atproto_signing.is_some()
                    || entry.atproto_pds.is_some()
                {
                    Err(anyhow!("Tombstone has unexpected entries"))
                } else {
                    Ok(plc::Operation::Tombstone(plc::TombstoneOp {
                        prev: prev.ok_or_else(|| anyhow!("Tombstone op missing prev"))?,
                    }))
                }
            }
            "C" => {
                if !(rotation_keys.len() == 2
                    && verification_methods.is_empty()
                    && services.is_empty())
                {
                    return Err(anyhow!("Legacy create op has unexpected entries"));
                }

                let mut rotation_keys = rotation_keys.into_iter();
                let recovery_key = rotation_keys.next().expect("present");
                if rotation_keys.next() != entry.atproto_signing {
                    return Err(anyhow!(
                        "Legacy create op {} has secondary rotation key mismatch",
                        cid.as_ref(),
                    ));
                }

                let handle = match entry
                    .also_known_as
                    .ok_or_else(|| anyhow!("Missing also_known_as"))?
                {
                    serde_json::Value::Array(v) => {
                        if v.len() == 1 {
                            match v.into_iter().next().expect("present") {
                                serde_json::Value::String(s) => s
                                    .strip_prefix("at://")
                                    .map(String::from)
                                    .ok_or_else(|| anyhow!("also_known_as missing prefix")),
                                _ => Err(anyhow!("also_known_as does not contain strings")),
                            }
                        } else {
                            Err(anyhow!("Legacy create op also_known_as is not length 1"))
                        }
                    }
                    _ => Err(anyhow!("also_known_as is not an array")),
                }?;

                Ok(plc::Operation::LegacyCreate(plc::LegacyCreateOp {
                    signing_key: entry
                        .atproto_signing
                        .ok_or_else(|| anyhow!("Legacy create op missing signing_key"))?,
                    recovery_key,
                    handle,
                    service: entry
                        .atproto_pds
                        .ok_or_else(|| anyhow!("Legacy create op missing atproto_pds"))?,
                    prev: (),
                }))
            }
            s => Err(anyhow!("Unknown operation type {s}")),
        }?;

        let operation = plc::SignedOperation {
            content,
            sig: entry.sig,
        };

        if operation.cid() == cid {
            Ok(plc::LogEntry {
                did: entry.did.map_err(|e| anyhow!("{e}"))?,
                operation,
                cid,
                nullified: entry.nullified,
                created_at: entry.created_at?,
            })
        } else {
            Err(anyhow!(
                "Internal server error: CID mismatch for {}",
                cid.as_ref(),
            ))
        }
    }
}
