use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};
use std::iter;

use atrium_api::types::string::{Cid, Datetime, Did};
use atrium_crypto::keypair::{Did as _, Export, P256Keypair};
use base64ct::Encoding;
use chrono::Duration;
use rand_core::OsRng;

use super::{AuditLog, ChangeOp, LegacyCreateOp, LogEntry, Operation, SignedOperation};
use crate::{
    data::{PlcData, Service, ATPROTO_PDS_KIND, ATPROTO_PDS_TYPE, ATPROTO_VERIFICATION_METHOD},
    util::derive_did,
};

/// The state of an identity as of a particular operation.
struct Identity {
    rotation: Vec<P256Keypair>,
    signing: HashMap<String, P256Keypair>,
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        Self {
            rotation: self
                .rotation
                .iter()
                .map(|key| P256Keypair::import(&key.export()).unwrap())
                .collect(),
            signing: self
                .signing
                .iter()
                .map(|(service, key)| {
                    (service.clone(), P256Keypair::import(&key.export()).unwrap())
                })
                .collect(),
        }
    }
}

impl Identity {
    fn generate() -> Self {
        let mut rng = OsRng;

        Self {
            rotation: vec![P256Keypair::create(&mut rng), P256Keypair::create(&mut rng)],
            signing: iter::once((
                ATPROTO_VERIFICATION_METHOD.into(),
                P256Keypair::create(&mut rng),
            ))
            .collect(),
        }
    }
}

pub(crate) struct TestLog {
    initial_state: Identity,
    state_updates: Vec<(usize, Identity)>,
    did: Did,
    entries: Vec<LogEntry>,
}

impl TestLog {
    pub(crate) fn empty(did: Did) -> Self {
        Self {
            initial_state: Identity::generate(),
            state_updates: vec![],
            did,
            entries: vec![],
        }
    }

    /// Creates a valid log with a single operation.
    pub(crate) fn with_genesis() -> Self {
        let initial_state = Identity::generate();

        let content = Operation::Change(ChangeOp {
            data: PlcData {
                rotation_keys: initial_state.rotation.iter().map(|key| key.did()).collect(),
                verification_methods: initial_state
                    .signing
                    .iter()
                    .map(|(k, v)| (k.clone(), v.did()))
                    .collect(),
                also_known_as: vec!["at://example.com".into()],
                services: [(
                    ATPROTO_PDS_KIND.into(),
                    Service {
                        r#type: ATPROTO_PDS_TYPE.into(),
                        endpoint: "https://bsky.social".into(),
                    },
                )]
                .into_iter()
                .collect(),
            },
            prev: None,
        });

        let operation = add_signature(
            content,
            initial_state.rotation.last().unwrap(),
            SigKind::Normal,
        );
        let did = derive_did(&operation.signed_bytes());
        let genesis = build_entry(did.clone(), operation, None);

        Self {
            initial_state,
            state_updates: vec![],
            did: genesis.did.clone(),
            entries: vec![genesis],
        }
    }

    /// Creates a valid log with a legacy genesis operation.
    pub(crate) fn with_legacy_genesis() -> Self {
        let mut initial_state = Identity::generate();

        // For legacy create ops, the signing key is also a rotation key.
        *initial_state
            .signing
            .get_mut(ATPROTO_VERIFICATION_METHOD)
            .unwrap() = P256Keypair::import(&initial_state.rotation[1].export()).unwrap();

        let content = Operation::LegacyCreate(LegacyCreateOp {
            signing_key: initial_state.rotation[1].did(),
            recovery_key: initial_state.rotation[0].did(),
            handle: "example.com".into(),
            service: "https://bsky.social".into(),
            prev: (),
        });

        let operation = add_signature(
            content,
            initial_state.rotation.last().unwrap(),
            SigKind::Normal,
        );
        let did = derive_did(&operation.signed_bytes());
        let genesis = build_entry(did.clone(), operation, None);

        Self {
            initial_state,
            state_updates: vec![],
            did: genesis.did.clone(),
            entries: vec![genesis],
        }
    }

    pub(crate) fn apply_update<F: FnOnce(Update) -> Update>(self, f: F) -> Self {
        f(Update::new(self)).build()
    }

    pub(crate) fn apply_tombstone<F: FnOnce(Tombstone) -> Tombstone>(self, f: F) -> Self {
        f(Tombstone::new(self)).build()
    }

    /// Swaps the operations at the given positions in the log, preserving their order
    /// within the operation chain.
    pub(crate) fn swap_in_log(&mut self, a: usize, b: usize) {
        self.entries.swap(a, b);
    }

    /// Swaps the operations at the given positions in the log, and also swaps their
    /// `prev` pointers to swap their order in the operations chain.
    pub(crate) fn swap_in_chain(&mut self, a: usize, b: usize) {
        // Normalize the order to make the implementation easier.
        let (a, b) = match a.cmp(&b) {
            Ordering::Less => (a, b),
            Ordering::Equal => panic!("Cannot swap an operation with itself"),
            Ordering::Greater => (b, a),
        };

        let get_links = |entry: &LogEntry| {
            (
                entry.cid.clone(),
                match &entry.operation.content {
                    Operation::Change(op) => op.prev.clone(),
                    Operation::Tombstone(op) => Some(op.prev.clone()),
                    Operation::LegacyCreate(_) => None,
                },
            )
        };

        let set_prev = |entry: &mut LogEntry, prev| match &mut entry.operation.content {
            Operation::Change(op) => op.prev = prev,
            Operation::Tombstone(op) => op.prev = prev.expect("should swap compatible operations"),
            Operation::LegacyCreate(_) => assert!(prev.is_none()),
        };

        let (a_cid, a_prev) = get_links(&self.entries[a]);
        let (b_cid, b_prev) = get_links(&self.entries[b]);

        // TODO: This isn't swapping the `prev` pointers that point *to* them from child
        // entries, thus breaking the chain. Maybe we need a better way to construct this.
        match (a_prev, b_prev) {
            // Two genesis operations; nothing to do.
            (None, None) => (),
            //    A <-- B
            // => B <-- A
            (None, Some(prev)) if prev == a_cid => {
                set_prev(&mut self.entries[a], Some(b_cid));
                set_prev(&mut self.entries[b], None);
            }
            //    A <-- ... prev <-- B
            // => B <-- ... prev <-- A
            (None, Some(prev)) => {
                set_prev(&mut self.entries[a], Some(prev));
                set_prev(&mut self.entries[b], None);
            }
            //    A --> B
            // => B --> A
            (Some(prev), None) if prev == b_cid => {
                set_prev(&mut self.entries[a], None);
                set_prev(&mut self.entries[b], Some(a_cid));
            }
            //    A --> prev ... --> B
            // => B --> prev ... --> A
            (Some(prev), None) => {
                set_prev(&mut self.entries[a], None);
                set_prev(&mut self.entries[b], Some(prev));
            }
            //    prev <-- A <-- B
            // => prev <-- B <-- A
            (Some(a_prev), Some(b_prev)) if b_prev == a_cid => {
                set_prev(&mut self.entries[a], Some(b_cid));
                set_prev(&mut self.entries[b], Some(a_prev));
            }
            //    prev <-- B <-- A
            // => prev <-- A <-- B
            (Some(a_prev), Some(b_prev)) if a_prev == b_cid => {
                set_prev(&mut self.entries[a], Some(b_prev));
                set_prev(&mut self.entries[b], Some(a_cid));
            }
            //    _ <-- A ... _ <-- B
            // => _ <-- B ... _ <-- A
            (Some(a_prev), Some(b_prev)) => {
                set_prev(&mut self.entries[a], Some(b_prev));
                set_prev(&mut self.entries[b], Some(a_prev));
            }
        }

        self.entries.swap(a, b);
    }

    /// Removes and returns the operation at the given position.
    pub(crate) fn remove(&mut self, operation: usize) -> LogEntry {
        self.entries.remove(operation)
    }

    /// Derives the correct DID for the log.
    pub(crate) fn did(&self) -> Did {
        derive_did(
            &self
                .entries
                .first()
                .expect("log is not empty")
                .operation
                .signed_bytes(),
        )
    }

    /// Returns the claimed DID for the log.
    pub(crate) fn claimed_did(&self) -> Did {
        self.did.clone()
    }

    /// Derives the correct CID for the given operation.
    pub(crate) fn cid_for(&self, operation: usize) -> Cid {
        self.entries
            .get(operation)
            .expect("operation exists")
            .operation
            .cid()
    }

    /// Returns the claimed CID for the given operation.
    pub(crate) fn claimed_cid_for(&self, operation: usize) -> Cid {
        self.entries
            .get(operation)
            .expect("operation exists")
            .cid
            .clone()
    }

    /// Returns the audit log corresponding to the current state.
    pub(crate) fn audit_log(&self) -> AuditLog {
        AuditLog::new(self.did.clone(), self.entries.clone())
    }
}

pub(crate) struct Update {
    log: TestLog,
    new_rotation_keys: HashMap<usize, P256Keypair>,
    removed_rotation_keys: BTreeSet<usize>,
    new_signing_key: Option<P256Keypair>,
    new_handle: Option<Option<String>>,
    new_pds: Option<Option<String>>,
    with_prev: Option<Option<Cid>>,
    signed_with_key: Option<KeyKind>,
    sig_kind: SigKind,
    nullified: bool,
    created_at: Option<Datetime>,
}

impl Update {
    fn new(log: TestLog) -> Self {
        Self {
            log,
            new_rotation_keys: HashMap::new(),
            removed_rotation_keys: BTreeSet::new(),
            new_signing_key: None,
            new_handle: None,
            new_pds: None,
            with_prev: None,
            signed_with_key: None,
            sig_kind: SigKind::Normal,
            nullified: false,
            created_at: None,
        }
    }

    pub(crate) fn rotate_rotation_key(mut self, authority: usize) -> Self {
        let mut rng = OsRng;
        assert!(self
            .new_rotation_keys
            .insert(authority, P256Keypair::create(&mut rng))
            .is_none());
        self
    }

    pub(crate) fn remove_rotation_key(mut self, authority: usize) -> Self {
        assert!(self.removed_rotation_keys.insert(authority));
        self
    }

    pub(crate) fn rotate_signing_key(mut self) -> Self {
        assert!(self.new_signing_key.is_none());
        let mut rng = OsRng;
        self.new_signing_key = Some(P256Keypair::create(&mut rng));
        self
    }

    pub(crate) fn change_handle(mut self, handle: &str) -> Self {
        assert!(self.new_handle.is_none());
        self.new_handle = Some(Some(handle.into()));
        self
    }

    pub(crate) fn remove_handle(mut self) -> Self {
        assert!(self.new_handle.is_none());
        self.new_handle = Some(None);
        self
    }

    pub(crate) fn change_pds(mut self, pds: &str) -> Self {
        assert!(self.new_pds.is_none());
        self.new_pds = Some(Some(pds.into()));
        self
    }

    pub(crate) fn remove_pds(mut self) -> Self {
        assert!(self.new_pds.is_none());
        self.new_pds = Some(None);
        self
    }

    pub(crate) fn with_prev_op(mut self, prev: usize) -> Self {
        assert!(self.with_prev.is_none());
        self.with_prev = Some(Some(self.log.cid_for(prev)));
        self
    }

    pub(crate) fn with_prev_cid(mut self, prev: Cid) -> Self {
        assert!(self.with_prev.is_none());
        self.with_prev = Some(Some(prev));
        self
    }

    pub(crate) fn without_prev(mut self) -> Self {
        assert!(self.with_prev.is_none());
        self.with_prev = Some(None);
        self
    }

    pub(crate) fn signed_with_key(mut self, authority: usize) -> Self {
        assert!(self.signed_with_key.is_none());
        self.signed_with_key = Some(KeyKind::Rotation {
            operation: None,
            authority,
        });
        self
    }

    pub(crate) fn signed_with_key_from(mut self, operation: usize, authority: usize) -> Self {
        assert!(self.signed_with_key.is_none());
        self.signed_with_key = Some(KeyKind::Rotation {
            operation: Some(operation),
            authority,
        });
        self
    }

    pub(crate) fn signed_with_signing_key(mut self) -> Self {
        assert!(self.signed_with_key.is_none());
        self.signed_with_key = Some(KeyKind::Signing);
        self
    }

    pub(crate) fn padded_sig(mut self) -> Self {
        self.sig_kind = SigKind::Padded;
        self
    }

    pub(crate) fn invalid_sig(mut self) -> Self {
        self.sig_kind = SigKind::Invalid;
        self
    }

    pub(crate) fn nullified(mut self) -> Self {
        self.nullified = true;
        self
    }

    pub(crate) fn created_after(mut self, operation: usize, delta: Duration) -> Self {
        assert!(self.created_at.is_none());
        self.created_at = Some(Datetime::new(
            *self
                .log
                .entries
                .get(operation)
                .expect("operation exists")
                .created_at
                .as_ref()
                + delta,
        ));
        self
    }

    fn build(self) -> TestLog {
        let mut log = self.log;

        let prev_op = log.entries.last().expect("non-empty");

        let mut new_data = match &prev_op.operation.content {
            Operation::Change(op) => op.data.clone(),
            Operation::Tombstone(op) => {
                // We're constructing an invalid test case; grab the necessary data from
                // the most recent non-tombstone operation.
                let mut prev = op.prev.clone();
                loop {
                    match &log
                        .entries
                        .iter()
                        .find(|entry| entry.cid == prev)
                        .expect("Updating a tombstone with no non-tombstone prev is unsupported")
                        .operation
                        .content
                    {
                        Operation::Change(op) => break op.data.clone(),
                        Operation::Tombstone(op) => prev = op.prev.clone(),
                        Operation::LegacyCreate(op) => break op.clone().into_plc_data(),
                    }
                }
            }
            Operation::LegacyCreate(op) => op.clone().into_plc_data(),
        };

        if !(self.new_rotation_keys.is_empty()
            && self.removed_rotation_keys.is_empty()
            && self.new_signing_key.is_none())
        {
            let mut new_state = log
                .state_updates
                .last()
                .map(|(_, state)| state)
                .unwrap_or(&log.initial_state)
                .clone();

            for (authority, key) in self.new_rotation_keys {
                if let Some(rotation_key) = new_data.rotation_keys.get_mut(authority) {
                    *rotation_key = key.did();
                    *new_state.rotation.get_mut(authority).expect("present") = key;
                } else {
                    assert_eq!(new_data.rotation_keys.len(), authority);
                    assert_eq!(new_state.rotation.len(), authority);
                    new_data.rotation_keys.push(key.did());
                    new_state.rotation.push(key);
                }
            }

            for authority in self.removed_rotation_keys.into_iter().rev() {
                new_data.rotation_keys.remove(authority);
                new_state.rotation.remove(authority);
            }

            if let Some(new_signing_key) = self.new_signing_key {
                new_data
                    .verification_methods
                    .insert(ATPROTO_VERIFICATION_METHOD.into(), new_signing_key.did());
                new_state
                    .signing
                    .insert(ATPROTO_VERIFICATION_METHOD.into(), new_signing_key);
            }

            log.state_updates.push((log.entries.len(), new_state));
        }

        match self.new_handle {
            Some(Some(handle)) => {
                if let Some(primary_handle) = new_data.also_known_as.get_mut(0) {
                    *primary_handle = handle;
                } else {
                    assert!(new_data.also_known_as.is_empty());
                    new_data.also_known_as.push(handle);
                }
            }
            Some(None) if !new_data.also_known_as.is_empty() => {
                new_data.also_known_as.remove(0);
            }
            _ => (),
        }

        match self.new_pds {
            Some(Some(endpoint)) => {
                if let Some(service) = new_data.services.get_mut(ATPROTO_PDS_KIND) {
                    service.endpoint = endpoint;
                } else {
                    new_data.services.insert(
                        ATPROTO_PDS_KIND.into(),
                        Service {
                            r#type: ATPROTO_PDS_TYPE.into(),
                            endpoint,
                        },
                    );
                }
            }
            Some(None) => {
                new_data.services.remove(ATPROTO_PDS_KIND);
            }
            _ => (),
        }

        let operation = sign_operation(
            Operation::Change(ChangeOp {
                data: new_data,
                prev: self.with_prev.unwrap_or(Some(prev_op.cid.clone())),
            }),
            &log,
            self.signed_with_key,
            self.sig_kind,
        );

        let mut new_entry = build_entry(log.did.clone(), operation, self.created_at);
        new_entry.nullified = self.nullified;

        log.entries.push(new_entry);

        log
    }
}

pub(crate) struct Tombstone {
    log: TestLog,
    with_prev: Option<Cid>,
    signed_with_key: Option<KeyKind>,
    sig_kind: SigKind,
    nullified: bool,
    created_at: Option<Datetime>,
}

impl Tombstone {
    fn new(log: TestLog) -> Self {
        Self {
            log,
            with_prev: None,
            signed_with_key: None,
            sig_kind: SigKind::Normal,
            nullified: false,
            created_at: None,
        }
    }

    pub(crate) fn with_prev_op(mut self, prev: usize) -> Self {
        assert!(self.with_prev.is_none());
        self.with_prev = Some(self.log.cid_for(prev));
        self
    }

    pub(crate) fn with_prev_cid(mut self, prev: Cid) -> Self {
        assert!(self.with_prev.is_none());
        self.with_prev = Some(prev);
        self
    }

    pub(crate) fn signed_with_key(mut self, authority: usize) -> Self {
        assert!(self.signed_with_key.is_none());
        self.signed_with_key = Some(KeyKind::Rotation {
            operation: None,
            authority,
        });
        self
    }

    pub(crate) fn signed_with_key_from(mut self, operation: usize, authority: usize) -> Self {
        assert!(self.signed_with_key.is_none());
        self.signed_with_key = Some(KeyKind::Rotation {
            operation: Some(operation),
            authority,
        });
        self
    }

    pub(crate) fn signed_with_signing_key(mut self) -> Self {
        assert!(self.signed_with_key.is_none());
        self.signed_with_key = Some(KeyKind::Signing);
        self
    }

    pub(crate) fn padded_sig(mut self) -> Self {
        self.sig_kind = SigKind::Padded;
        self
    }

    pub(crate) fn invalid_sig(mut self) -> Self {
        self.sig_kind = SigKind::Invalid;
        self
    }

    pub(crate) fn nullified(mut self) -> Self {
        self.nullified = true;
        self
    }

    pub(crate) fn created_after(mut self, operation: usize, delta: Duration) -> Self {
        assert!(self.created_at.is_none());
        self.created_at = Some(Datetime::new(
            *self
                .log
                .entries
                .get(operation)
                .expect("operation exists")
                .created_at
                .as_ref()
                + delta,
        ));
        self
    }

    fn build(self) -> TestLog {
        let mut log = self.log;

        let prev_op = log.entries.last().expect("non-empty");

        let operation = sign_operation(
            Operation::Tombstone(super::TombstoneOp {
                prev: self.with_prev.unwrap_or(prev_op.cid.clone()),
            }),
            &log,
            self.signed_with_key,
            self.sig_kind,
        );

        let mut new_entry = build_entry(log.did.clone(), operation, self.created_at);
        new_entry.nullified = self.nullified;

        log.entries.push(new_entry);

        log
    }
}

enum KeyKind {
    Rotation {
        operation: Option<usize>,
        authority: usize,
    },
    Signing,
}

enum SigKind {
    Normal,
    Padded,
    Invalid,
}

fn sign_operation(
    content: Operation,
    log: &TestLog,
    signed_with_key: Option<KeyKind>,
    sig_kind: SigKind,
) -> SignedOperation {
    fn get_state(log: &TestLog, operation: Option<usize>) -> &Identity {
        log.state_updates
            .iter()
            .rev()
            .find_map(|(i, state)| {
                (*i < operation.map_or_else(|| log.entries.len(), |a| a + 1)).then_some(state)
            })
            .unwrap_or(&log.initial_state)
    }

    match signed_with_key {
        None => {
            // By default, sign with least authority.
            let key = get_state(log, None).rotation.last().unwrap();
            add_signature(content, key, sig_kind)
        }
        Some(KeyKind::Rotation {
            operation,
            authority,
        }) => {
            let key = &get_state(log, operation)
                .rotation
                .get(authority)
                .expect("Rotation key with authority must exist");

            add_signature(content, key, sig_kind)
        }
        Some(KeyKind::Signing) => {
            let key = get_state(log, None)
                .signing
                .get(ATPROTO_VERIFICATION_METHOD)
                .expect("exists");
            add_signature(content, key, sig_kind)
        }
    }
}

fn add_signature(content: Operation, key: &P256Keypair, sig_kind: SigKind) -> SignedOperation {
    let unsigned = content.unsigned_bytes();

    let sig_bytes = &key
        .sign(match sig_kind {
            SigKind::Invalid => &[],
            _ => &unsigned[..],
        })
        .unwrap();

    let sig = match sig_kind {
        SigKind::Padded => base64ct::Base64Url::encode_string(sig_bytes),
        _ => base64ct::Base64UrlUnpadded::encode_string(sig_bytes),
    };

    SignedOperation { content, sig }
}

fn build_entry(did: Did, operation: SignedOperation, created_at: Option<Datetime>) -> LogEntry {
    let cid = operation.cid();

    LogEntry {
        did,
        operation,
        cid,
        nullified: false,
        created_at: created_at.unwrap_or_else(Datetime::now),
    }
}
