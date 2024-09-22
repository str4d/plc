use std::collections::BTreeMap;

use atrium_api::types::string::{Cid, Datetime, Did};
use cid::multihash::Multihash;
use diff::Diff;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    data::{
        PlcData, PlcDataDiff, Service, State, ATPROTO_PDS_KIND, ATPROTO_PDS_TYPE,
        ATPROTO_VERIFICATION_METHOD,
    },
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

#[cfg(feature = "mirror")]
pub(crate) async fn export(
    after: Option<&Datetime>,
    client: &Client,
) -> Result<Vec<LogEntry>, Error> {
    if let Some(d) = &after {
        tracing::info!("Exporting log entries after {}", d.as_str());
    } else {
        tracing::info!("Exporting initial log entries");
    }

    let url = if let Some(after) = after {
        format!(
            "https://plc.directory/export?count=1000&after={}",
            after.as_str(),
        )
    } else {
        "https://plc.directory/export?count=1000".into()
    };

    let resp = client
        .get(url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|_| Error::PlcDirectoryRequestFailed)?;

    let entries = resp
        .text()
        .await
        .map_err(|_| Error::PlcDirectoryReturnedInvalidLogEntries)?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()
        .map_err(|_| Error::PlcDirectoryReturnedInvalidLogEntries)?;

    Ok(entries)
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LogEntry {
    pub(crate) did: Did,
    pub(crate) operation: SignedOperation,
    pub(crate) cid: Cid,
    pub(crate) nullified: bool,
    pub(crate) created_at: Datetime,
}

impl LogEntry {
    pub(crate) fn into_state(self) -> Option<State> {
        match self.operation.content {
            Operation::Change(op) => Some(State {
                did: self.did,
                plc: op.data,
            }),
            Operation::Tombstone(_) => None,
            Operation::LegacyCreate(op) => Some(State {
                did: self.did,
                plc: op.into_plc_data(),
            }),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SignedOperation {
    #[serde(flatten)]
    pub(crate) content: Operation,
    /// Signature of the operation in `base64url` encoding.
    pub(crate) sig: String,
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
    pub(crate) fn cid(&self) -> Cid {
        Cid::new(cid::Cid::new_v1(
            0x71,
            Multihash::wrap(0x12, &Sha256::digest(self.signed_bytes())).expect("correct length"),
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub(crate) enum Operation {
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
pub(crate) struct ChangeOp {
    #[serde(flatten)]
    pub(crate) data: PlcData,
    /// A CID hash pointer to a previous operation if an update, or `None` for a creation.
    ///
    /// If `None`, the key should actually be part of the object, with value `None`, not
    /// simply omitted.
    ///
    /// In DAG-CBOR encoding, the CID is string-encoded, not a binary IPLD "Link".
    pub(crate) prev: Option<Cid>,
    /// Thanks to @retr0.id for sponsoring this field.
    #[serde(flatten)]
    pub(crate) extra_fields: BTreeMap<String, Value>,
}

impl ChangeOp {
    fn rotation_keys(&self) -> impl Iterator<Item = &str> {
        self.data.rotation_keys.iter().map(|s| s.as_str())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct TombstoneOp {
    /// A CID hash pointer to a previous operation.
    ///
    /// In DAG-CBOR encoding, the CID is string-encoded, not a binary IPLD "Link".
    pub(crate) prev: Cid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LegacyCreateOp {
    /// A `did:key` value.
    pub(crate) signing_key: String,
    /// A `did:key` value.
    pub(crate) recovery_key: String,
    /// A bare ATProto handle, with no `at://` prefix.
    pub(crate) handle: String,
    /// HTTP/HTTPS URL of an ATProto PDS.
    pub(crate) service: String,
    /// Always `null`.
    pub(crate) prev: (),
}

impl LegacyCreateOp {
    fn rotation_keys(&self) -> impl Iterator<Item = &str> {
        [self.recovery_key.as_str(), self.signing_key.as_str()].into_iter()
    }

    pub(crate) fn into_plc_data(self) -> PlcData {
        PlcData {
            rotation_keys: self.rotation_keys().map(String::from).collect(),
            verification_methods: Some((ATPROTO_VERIFICATION_METHOD.into(), self.signing_key))
                .into_iter()
                .collect(),
            also_known_as: vec![format!("at://{}", self.handle)],
            services: Some((
                ATPROTO_PDS_KIND.into(),
                Service {
                    r#type: ATPROTO_PDS_TYPE.into(),
                    endpoint: self.service,
                },
            ))
            .into_iter()
            .collect(),
        }
    }
}
