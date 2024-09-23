use std::collections::HashMap;
use std::fmt;

use atrium_api::types::string::{Cid, Did};
use atrium_crypto::did::parse_did_key;
use base64ct::Encoding;

use crate::util::derive_did;

use super::{LogEntry, Operation};

#[cfg(test)]
mod tests;

const RECOVERY_WINDOW: chrono::TimeDelta = chrono::TimeDelta::hours(72);

/// Time before which a [`LogEntry`] is permitted to have a malleable signature.
///
/// https://github.com/did-method-plc/did-method-plc/pull/54 changed the behaviour of
/// plc.directory to prevent signature malleability. Prior to the time at which this PR
/// was merged, the following malleability was permitted:
///
/// - The Base64 encoding of signatures could contain padding.
/// - Signatures could be DER-encoded.
/// - High-S signatures were permitted.
const MALLEABILITY_PREVENTED: chrono::DateTime<chrono::Utc> =
    chrono::DateTime::from_timestamp_nanos(1_701_370_214_000_000_000);

#[derive(Debug)]
pub(crate) struct AuditLog {
    did: Did,
    entries: Vec<LogEntry>,
}

impl AuditLog {
    pub(crate) fn new(did: Did, entries: Vec<LogEntry>) -> Self {
        Self { did, entries }
    }

    pub(crate) fn validate(&self) -> Result<(), Vec<AuditError>> {
        let mut errors = vec![];

        // For the genesis operation, validate the DID.
        match self.entries.first() {
            None => errors.push(AuditError::AuditLogEmpty),
            Some(entry) => {
                let mut validate_did = |signed_bytes| {
                    let did = derive_did(signed_bytes);
                    if did != self.did {
                        errors.push(AuditError::GenesisOperationInvalidDid {
                            expected: self.did.clone(),
                            actual: did,
                        })
                    }
                };

                match &entry.operation.content {
                    Operation::Change(op) if op.prev.is_none() => {
                        validate_did(&entry.operation.signed_bytes())
                    }
                    Operation::LegacyCreate(_) => validate_did(&entry.operation.signed_bytes()),
                    _ => errors.push(AuditError::GenesisOperationNotCreate),
                }
            }
        }

        // Track the graph of operations.
        type EntryWithAuthority<'a> = (&'a LogEntry, Option<usize>);
        let mut active_graph: HashMap<&Cid, (Option<EntryWithAuthority>, Vec<EntryWithAuthority>)> =
            HashMap::new();

        for (i, entry) in self.entries.iter().enumerate() {
            // Perform non-contextual validation.
            if let Err(e) = entry.validate_self(&self.did) {
                errors.extend(e);
            }

            // Find the operation declared as immediately prior to this one, if any.
            let find_prev = |prev: &Cid| {
                let (past, future) = self.entries.split_at(i);

                if let Some(entry) = past.iter().find(|entry| &entry.cid == prev) {
                    Ok(entry)
                } else if future.iter().any(|entry| &entry.cid == prev) {
                    // Audit log operations should be correctly ordered.
                    Err(AuditError::PrevReferencesFuture {
                        cid: entry.cid.clone(),
                        prev: prev.clone(),
                    })
                } else {
                    Err(AuditError::PrevMissing { prev: prev.clone() })
                }
            };

            let prev = match &entry.operation.content {
                Operation::Change(op) => op.prev.as_ref().map(find_prev).transpose(),
                Operation::Tombstone(op) => find_prev(&op.prev).map(Some),
                Operation::LegacyCreate(_) => Ok(None),
            };

            match prev {
                // We could not locate the declared most-recent previous operation.
                // We can't perform any more checks on this entry.
                Err(e) => errors.push(e),

                // Either this is a genesis operation, or we located its most-recent
                // previous operation.
                Ok(prev) => {
                    let (res, signer_authority) = entry.validate_with_prev(prev);
                    if let Err(e) = res {
                        errors.extend(e);
                    }

                    // For non-genesis operations:
                    if let Some(prev) = prev {
                        let (active_child, nullified_children) = active_graph
                            .entry(&prev.cid)
                            .or_insert_with(|| (None, vec![]));

                        // Verify the correctness of "nullified" operations and the current
                        // active operation log using the rules around rotation keys and
                        // recovery windows.
                        if entry.nullified {
                            // Either `prev` must be nullified, or `prev` must have an
                            // active child operation within the recovery window from this
                            // entry.
                            if !prev.nullified {
                                // Multiple operations can have the same `prev`; a child
                                // can be nullified as long as it is not after the active
                                // child.
                                if active_child.is_some() {
                                    errors.push(AuditError::EntryIncorrectlyNullified {
                                        cid: entry.cid.clone(),
                                    });
                                } else {
                                    nullified_children.push((entry, signer_authority));
                                }
                            }
                        } else if prev.nullified {
                            errors.push(AuditError::EntryIncorrectlyActive {
                                cid: entry.cid.clone(),
                            });
                        } else if let Some((earlier_entry, earlier_signer_authority)) =
                            &active_child
                        {
                            // An operation can't have two active children. Check which
                            // one has higher authority.
                            if entry.nullifies(
                                signer_authority,
                                earlier_entry,
                                *earlier_signer_authority,
                            ) {
                                errors.push(AuditError::EntryIncorrectlyActive {
                                    cid: earlier_entry.cid.clone(),
                                });

                                // Set the correct (as of now) active child, so we can
                                // perform the equivalent check with subsequent
                                // operations if necessary.
                                *active_child = Some((entry, signer_authority));
                            } else {
                                errors.push(AuditError::MultipleActiveChildren {
                                    cid: entry.cid.clone(),
                                    first: earlier_entry.cid.clone(),
                                });
                            }
                        } else {
                            let mut entry_incorrectly_active = false;

                            for i in (0..nullified_children.len()).rev() {
                                let (nullified_entry, nullified_signer_authority) =
                                    nullified_children.get(i).expect("present");
                                if entry.nullifies(
                                    signer_authority,
                                    nullified_entry,
                                    *nullified_signer_authority,
                                ) {
                                    // We confirmed this was nullified correctly, so
                                    // we don't need to check it anymore.
                                    nullified_children.remove(i);
                                } else {
                                    entry_incorrectly_active |= true;
                                }
                            }

                            if entry_incorrectly_active {
                                errors.push(AuditError::EntryIncorrectlyActive {
                                    cid: entry.cid.clone(),
                                });
                            }

                            // Mark this as the active child even if it is incorrectly
                            // active, so that we can detect multiple active children,
                            // and out-of-order nullified children.
                            *active_child = Some((entry, signer_authority));
                        }
                    } else {
                        if i != 0 {
                            // Genesis operations can only occur once, at the start.
                            errors.push(AuditError::NonGenesisCreate {
                                cid: entry.cid.clone(),
                            });
                        }
                        if entry.nullified {
                            // Genesis operations cannot be nullified.
                            errors.push(AuditError::EntryIncorrectlyNullified {
                                cid: entry.cid.clone(),
                            });
                        }
                    }
                }
            }
        }

        // Any nullified children that remain in the active graph were incorrectly
        // nullified.
        for (_, (_, nullified_children)) in active_graph {
            for (nullified_entry, _) in nullified_children {
                errors.push(AuditError::EntryIncorrectlyNullified {
                    cid: nullified_entry.cid.clone(),
                });
            }
        }

        if errors.is_empty() {
            // Everything is okay!
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl LogEntry {
    fn validate_self(&self, did: &Did) -> Result<(), Vec<AuditError>> {
        let mut errors = vec![];

        // Check the CID is correct.
        let cid = self.operation.cid();
        if self.cid != cid {
            errors.push(AuditError::EntryCidInvalid {
                cid: self.cid.clone(),
                actual: cid,
            });
        }

        // Check that the audit log entries all have the same DID.
        if &self.did != did {
            errors.push(AuditError::EntryDidMismatch {
                cid: self.cid.clone(),
            });
        }

        if errors.is_empty() {
            // Everything is okay!
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn validate_with_prev(
        &self,
        prev: Option<&Self>,
    ) -> (Result<(), Vec<AuditError>>, Option<usize>) {
        let mut errors = vec![];

        let allow_malleable = self.created_at.as_ref() < &MALLEABILITY_PREVENTED;

        // Decode signature.
        let encoded_sig = if allow_malleable {
            self.operation.sig.trim_end_matches('=')
        } else {
            &self.operation.sig
        };
        let signature = match base64ct::Base64UrlUnpadded::decode_vec(encoded_sig) {
            Ok(signature) => Some(signature),
            Err(_) => {
                errors.push(AuditError::InvalidSignatureEncoding {
                    cid: self.cid.clone(),
                });
                None
            }
        };

        // Validate signature.
        let unsigned = self.operation.unsigned_bytes();
        let check_sig = |(_, did_key): &(_, &str)| {
            if let Some(sig) = &signature {
                parse_did_key(did_key)
                    .and_then(|(alg, public_key)| {
                        atrium_crypto::verify::Verifier::new(allow_malleable).verify(
                            alg,
                            &public_key,
                            &unsigned,
                            sig,
                        )
                    })
                    .is_ok()
            } else {
                // If we already raised an error for invalid signature
                // encoding, don't raise a separate error for a trust failure
                // (as this might just be a corrupted log entry, and the
                // uncorrupted log entry is fine). This has the side-effect
                // that the highest-authority rotation key will be considered
                // to have signed this event during `nullified` checking.
                true
            }
        };

        let check_signed = |signed| match signed {
            Some((index, _)) => Ok(index),
            None => Err(AuditError::TrustViolation {
                cid: self.cid.clone(),
            }),
        };

        let signature_valid = match (&self.operation.content, prev) {
            (Operation::Change(op), None) => {
                check_signed(op.rotation_keys().enumerate().find(check_sig))
            }
            (Operation::LegacyCreate(op), None) => {
                check_signed(op.rotation_keys().enumerate().find(check_sig))
            }
            (Operation::Change(_) | Operation::Tombstone(_), Some(prev)) => {
                match &prev.operation.content {
                    Operation::Change(op) => {
                        check_signed(op.rotation_keys().enumerate().find(check_sig))
                    }
                    Operation::LegacyCreate(op) => {
                        check_signed(op.rotation_keys().enumerate().find(check_sig))
                    }
                    Operation::Tombstone(_) => Err(AuditError::OperationAfterDeactivation {
                        cid: self.cid.clone(),
                        prev: prev.cid.clone(),
                    }),
                }
            }
            _ => unreachable!("see definition of prev above"),
        };

        // If the signature is valid, we now know the authority of the signer.
        let signer_authority = match signature_valid {
            Ok(index) => Some(index),
            Err(e) => {
                errors.push(e);
                None
            }
        };

        // For non-genesis operations:
        if let Some(prev) = prev {
            // Check that timestamps do not go backwards along a chain.
            if self.created_at < prev.created_at {
                errors.push(AuditError::EntryCreatedBeforePrev {
                    cid: self.cid.clone(),
                    prev: prev.cid.clone(),
                })
            }
        }

        (
            if errors.is_empty() {
                // Everything is okay!
                Ok(())
            } else {
                Err(errors)
            },
            signer_authority,
        )
    }

    fn nullifies(
        &self,
        signer_authority: Option<usize>,
        earlier_entry: &LogEntry,
        earlier_signer_authority: Option<usize>,
    ) -> bool {
        let submitted_in_time =
            *self.created_at.as_ref() <= *earlier_entry.created_at.as_ref() + RECOVERY_WINDOW;

        let current_is_higher_authority =
            match (signer_authority.as_ref(), earlier_signer_authority.as_ref()) {
                (Some(active_authority), Some(earlier_authority)) => {
                    active_authority < earlier_authority
                }
                // If we already raised a trust violation error for
                // the active entry, ensure we also raise an error
                // that it is incorrectly active.
                (None, _) => false,
                // If we only raised a trust violation error for the
                // nullified entry, we do not know whether the active
                // entry is incorrectly active (by this rule).
                (Some(_), None) => true,
            };

        submitted_in_time && current_is_higher_authority
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AuditError {
    AuditLogEmpty,
    EntryCidInvalid { cid: Cid, actual: Cid },
    EntryCreatedBeforePrev { cid: Cid, prev: Cid },
    EntryDidMismatch { cid: Cid },
    EntryIncorrectlyActive { cid: Cid },
    EntryIncorrectlyNullified { cid: Cid },
    InvalidSignatureEncoding { cid: Cid },
    GenesisOperationInvalidDid { expected: Did, actual: Did },
    GenesisOperationNotCreate,
    MultipleActiveChildren { cid: Cid, first: Cid },
    NonGenesisCreate { cid: Cid },
    OperationAfterDeactivation { cid: Cid, prev: Cid },
    PrevMissing { prev: Cid },
    PrevReferencesFuture { cid: Cid, prev: Cid },
    TrustViolation { cid: Cid },
}

#[cfg(not(tarpaulin_include))]
impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditError::AuditLogEmpty => write!(f, "Audit log is empty"),
            AuditError::EntryCidInvalid { cid, actual } => {
                write!(
                    f,
                    "Entry {} has actual CID {}",
                    cid.as_ref(),
                    actual.as_ref(),
                )
            }
            AuditError::EntryCreatedBeforePrev { cid, prev } => write!(
                f,
                "Entry {} has a creation time before its parent {}",
                cid.as_ref(),
                prev.as_ref(),
            ),
            AuditError::EntryDidMismatch { cid } => {
                write!(
                    f,
                    "DID in entry {} does not match genesis DID",
                    cid.as_ref(),
                )
            }
            AuditError::EntryIncorrectlyActive { cid } => write!(
                f,
                "Entry {} should be nullified but is active",
                cid.as_ref(),
            ),
            AuditError::EntryIncorrectlyNullified { cid } => write!(
                f,
                "Entry {} should be active but is nullified",
                cid.as_ref(),
            ),
            AuditError::InvalidSignatureEncoding { cid } => write!(
                f,
                "Signature for entry {} has invalid encoding",
                cid.as_ref(),
            ),
            AuditError::GenesisOperationInvalidDid { expected, actual } => write!(
                f,
                "Expected {} for genesis op, but derived {}",
                expected.as_str(),
                actual.as_str(),
            ),
            AuditError::GenesisOperationNotCreate => {
                write!(f, "The genesis operation is not a creation operation")
            }
            AuditError::MultipleActiveChildren { cid, first } => write!(
                f,
                "Entry {} has the same parent as entry {}",
                cid.as_ref(),
                first.as_ref(),
            ),
            AuditError::NonGenesisCreate { cid } => {
                write!(
                    f,
                    "Entry {} is a creation operation after the genesis operation",
                    cid.as_ref(),
                )
            }
            AuditError::OperationAfterDeactivation { cid, prev } => write!(
                f,
                "Entry {} attempts to chain from tombstone {}",
                cid.as_ref(),
                prev.as_ref(),
            ),
            AuditError::PrevMissing { prev } => write!(f, "Entry {} is missing", prev.as_ref()),
            AuditError::PrevReferencesFuture { cid, prev } => write!(
                f,
                "Entry {} references future entry {}",
                cid.as_ref(),
                prev.as_ref(),
            ),
            AuditError::TrustViolation { cid } => write!(
                f,
                "Signature for entry {} is not valid under any permitted rotation key",
                cid.as_ref(),
            ),
        }
    }
}
