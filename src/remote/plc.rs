use atrium_api::types::string::{Cid, Did};
use diff::Diff;
use reqwest::Client;
use serde::Deserialize;

use crate::{
    data::{PlcData, PlcDataDiff, Service, State},
    error::Error,
};

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
            }) => Ok(PlcData {
                rotation_keys: op.rotation_keys().map(String::from).collect(),
                verification_methods: Some(("atproto".into(), op.signing_key))
                    .into_iter()
                    .collect(),
                also_known_as: vec![format!("at://{}", op.handle)],
                services: Some((
                    "atproto_pds".into(),
                    Service {
                        r#type: "AtprotoPersonalDataServer".into(),
                        endpoint: op.service,
                    },
                ))
                .into_iter()
                .collect(),
            }),
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

#[derive(Debug, Deserialize)]
struct SignedOperation {
    #[serde(flatten)]
    content: Operation,
    /// Signature of the operation in `base64url` encoding.
    sig: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum Operation {
    #[serde(rename = "plc_operation")]
    Change(ChangeOp),
    #[serde(rename = "plc_tombstone")]
    Tombstone(TombstoneOp),
    #[serde(rename = "create")]
    LegacyCreate(LegacyCreateOp),
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
struct TombstoneOp {
    /// A CID hash pointer to a previous operation.
    ///
    /// In DAG-CBOR encoding, the CID is string-encoded, not a binary IPLD "Link".
    prev: Cid,
}

#[derive(Debug, Deserialize)]
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
}
