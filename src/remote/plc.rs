use atrium_api::types::string::{Cid, Datetime, Did};
use cid::multihash::Multihash;
use diff::Diff;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    data::{PlcData, PlcDataDiff, Service, State},
    error::Error,
};

mod audit;
pub(crate) use audit::AuditLog;

#[cfg(test)]
mod testing;

pub(crate) async fn get_state(did: &Did, client: &Client) -> Result<State, Error> {
    let resp = client
        .get(format!("https://plc.directory/{}/data", did.as_str()))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|_| Error::PlcDirectoryRequestFailed)?;

    resp.json::<State>()
        .await
        .map_err(|_| Error::PlcDirectoryReturnedInvalidDidDocument)
}

pub(crate) async fn get_ops_log(did: &Did, client: &Client) -> Result<OperationsLog, Error> {
    let resp = client
        .get(format!("https://plc.directory/{}/log", did.as_str()))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|_| Error::PlcDirectoryRequestFailed)?;

    let ops = resp
        .json()
        .await
        .map_err(|_| Error::PlcDirectoryReturnedInvalidOperationLog)?;

    OperationsLog::new(ops)
}

pub(crate) async fn get_audit_log(did: &Did, client: &Client) -> Result<AuditLog, Error> {
    let resp = client
        .get(format!("https://plc.directory/{}/log/audit", did.as_str()))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|_| Error::PlcDirectoryRequestFailed)?;

    let entries = resp
        .json()
        .await
        .map_err(|_| Error::PlcDirectoryReturnedInvalidAuditLog)?;

    Ok(AuditLog::new(did.clone(), entries))
}

#[derive(Debug)]
pub(crate) struct OperationsLog {
    pub(crate) create: PlcData,
    pub(crate) updates: Vec<PlcDataDiff>,
    pub(crate) deactivated: bool,
}

impl OperationsLog {
    fn new(mut ops: Vec<SignedOperation>) -> Result<Self, Error> {
        let deactivated = match ops.pop() {
            Some(SignedOperation {
                content: Operation::Tombstone(_),
                ..
            }) => true,
            Some(op) => {
                ops.push(op);
                false
            }
            None => false,
        };

        let mut ops = ops.into_iter();

        let create = match ops.next() {
            Some(SignedOperation {
                content: Operation::Change(op),
                ..
            }) if op.prev.is_none() => Ok(op.data),
            Some(SignedOperation {
                content: Operation::LegacyCreate(op),
                ..
            }) => Ok(op.into_plc_data()),
            _ => Err(Error::PlcDirectoryReturnedInvalidOperationLog),
        }?;

        let updates = ops
            .scan(create.clone(), |state, op| match op.content {
                Operation::Change(op) if op.prev.is_some() => {
                    let delta = state.diff(&op.data);
                    *state = op.data;
                    Some(Ok(delta))
                }
                _ => Some(Err(Error::PlcDirectoryReturnedInvalidOperationLog)),
            })
            .collect::<Result<_, _>>()?;

        Ok(Self {
            create,
            updates,
            deactivated,
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LogEntry {
    did: Did,
    operation: SignedOperation,
    cid: Cid,
    nullified: bool,
    created_at: Datetime,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SignedOperation {
    #[serde(flatten)]
    content: Operation,
    /// Signature of the operation in `base64url` encoding.
    sig: String,
}

impl SignedOperation {
    fn unsigned_bytes(&self) -> Vec<u8> {
        self.content.unsigned_bytes()
    }

    fn signed_bytes(&self) -> Vec<u8> {
        serde_ipld_dagcbor::to_vec(self).unwrap()
    }

    /// Computes the CID for this operation.
    ///
    /// This is used in `prev` references to prior operations.
    fn cid(&self) -> Cid {
        Cid::new(cid::Cid::new_v1(
            0x71,
            Multihash::wrap(0x12, &Sha256::digest(self.signed_bytes())).expect("correct length"),
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum Operation {
    #[serde(rename = "plc_operation")]
    Change(ChangeOp),
    #[serde(rename = "plc_tombstone")]
    Tombstone(TombstoneOp),
    #[serde(rename = "create")]
    LegacyCreate(LegacyCreateOp),
}

impl Operation {
    fn unsigned_bytes(&self) -> Vec<u8> {
        serde_ipld_dagcbor::to_vec(self).unwrap()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ChangeOp {
    #[serde(flatten)]
    data: PlcData,
    /// A CID hash pointer to a previous operation if an update, or `None` for a creation.
    ///
    /// If `None`, the key should actually be part of the object, with value `None`, not
    /// simply omitted.
    ///
    /// In DAG-CBOR encoding, the CID is string-encoded, not a binary IPLD "Link".
    prev: Option<Cid>,
}

impl ChangeOp {
    fn rotation_keys(&self) -> impl Iterator<Item = &str> {
        self.data.rotation_keys.iter().map(|s| s.as_str())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TombstoneOp {
    /// A CID hash pointer to a previous operation.
    ///
    /// In DAG-CBOR encoding, the CID is string-encoded, not a binary IPLD "Link".
    prev: Cid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyCreateOp {
    /// A `did:key` value.
    signing_key: String,
    /// A `did:key` value.
    recovery_key: String,
    /// A bare ATProto handle, with no `at://` prefix.
    handle: String,
    /// HTTP/HTTPS URL of an ATProto PDS.
    service: String,
    /// Always `null`.
    #[allow(dead_code)]
    prev: (),
}

impl LegacyCreateOp {
    fn rotation_keys(&self) -> impl Iterator<Item = &str> {
        [self.recovery_key.as_str(), self.signing_key.as_str()].into_iter()
    }

    pub(crate) fn into_plc_data(self) -> PlcData {
        PlcData {
            rotation_keys: self.rotation_keys().map(String::from).collect(),
            verification_methods: Some(("atproto".into(), self.signing_key))
                .into_iter()
                .collect(),
            also_known_as: vec![format!("at://{}", self.handle)],
            services: Some((
                "atproto_pds".into(),
                Service {
                    r#type: "AtprotoPersonalDataServer".into(),
                    endpoint: self.service,
                },
            ))
            .into_iter()
            .collect(),
        }
    }
}
