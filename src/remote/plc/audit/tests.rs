use atrium_api::types::string::Cid;
use chrono::Duration;

use crate::remote::plc::{audit::AuditError, testing::TestLog};

#[test]
fn valid_examples() {
    let log = TestLog::with_genesis();
    assert_eq!(log.audit_log().validate(), Ok(()));

    let log = log
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_update(|update| update.change_pds("pds.example.com"));
    assert_eq!(log.audit_log().validate(), Ok(()));

    let log = TestLog::with_legacy_genesis();
    assert_eq!(log.audit_log().validate(), Ok(()));

    let log = log
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_update(|update| update.change_pds("pds.example.com"));
    assert_eq!(log.audit_log().validate(), Ok(()));

    let log = TestLog::with_genesis().apply_update(|update| update.remove_handle());
    assert_eq!(log.audit_log().validate(), Ok(()));
    let log = log.apply_update(|update| update.change_handle("bob.example.com"));
    assert_eq!(log.audit_log().validate(), Ok(()));

    let log = TestLog::with_genesis().apply_update(|update| update.remove_pds());
    assert_eq!(log.audit_log().validate(), Ok(()));
    let log = log.apply_update(|update| update.change_pds("pds.example.com"));
    assert_eq!(log.audit_log().validate(), Ok(()));
}

#[test]
fn empty_log() {
    let log = TestLog::empty("did:plc:gyw3654yworelrygfwmqfv2y".parse().unwrap()).audit_log();
    assert_eq!(log.validate(), Err(vec![AuditError::AuditLogEmpty]));
}

#[test]
fn padded_sig() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com").padded_sig())
        .apply_update(|update| update.change_pds("pds.example.com"));

    assert_eq!(
        log.audit_log().validate(),
        Err(vec![AuditError::InvalidSignatureEncoding {
            cid: log.cid_for(1),
        }]),
    );
}

#[test]
fn invalid_sig() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com").invalid_sig())
        .apply_update(|update| update.change_pds("pds.example.com"));

    assert_eq!(
        log.audit_log().validate(),
        Err(vec![AuditError::TrustViolation {
            cid: log.cid_for(1),
        }]),
    );
}

#[test]
fn signed_with_signing_key() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_update(|update| {
            update
                .change_pds("pds.example.com")
                .signed_with_signing_key()
        });

    assert_eq!(
        log.audit_log().validate(),
        Err(vec![AuditError::TrustViolation {
            cid: log.cid_for(2),
        }]),
    );
}

#[test]
fn rotate_rotation_key() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_update(|update| update.rotate_rotation_key(0))
        .apply_update(|update| {
            update
                .change_pds("pds.example.com")
                .signed_with_key_from(2, 0)
        });

    assert_eq!(log.audit_log().validate(), Ok(()));
}

#[test]
fn sign_with_old_rotation_key() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_update(|update| update.rotate_rotation_key(0))
        .apply_update(|update| {
            update
                .change_pds("pds.example.com")
                .signed_with_key_from(1, 0)
        });

    assert_eq!(
        log.audit_log().validate(),
        Err(vec![AuditError::TrustViolation {
            cid: log.cid_for(3),
        }]),
    );
}

#[test]
fn remove_rotation_key() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_update(|update| update.remove_rotation_key(0))
        .apply_update(|update| {
            update
                .change_pds("pds.example.com")
                .signed_with_key_from(2, 0)
        });

    assert_eq!(log.audit_log().validate(), Ok(()));
}

#[test]
fn sign_with_removed_rotation_key() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_update(|update| update.remove_rotation_key(0))
        .apply_update(|update| {
            update
                .change_pds("pds.example.com")
                .signed_with_key_from(1, 0)
        });

    assert_eq!(
        log.audit_log().validate(),
        Err(vec![AuditError::TrustViolation {
            cid: log.cid_for(3),
        }]),
    );
}

#[test]
fn rotate_signing_key() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_update(|update| update.rotate_signing_key())
        .apply_update(|update| update.change_pds("pds.example.com"));

    assert_eq!(log.audit_log().validate(), Ok(()));
}

#[test]
fn missing_prev() {
    let nonexistent_cid: Cid = "bafyreiaegzwq2gvetzeaybcqy6f4a7ez6gdocmnz6c4uljh5exhn26oj4u"
        .parse()
        .unwrap();

    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_update(|update| {
            update
                .change_pds("pds.example.com")
                .with_prev_cid(nonexistent_cid.clone())
        });

    assert_eq!(
        log.audit_log().validate(),
        Err(vec![AuditError::PrevMissing {
            prev: nonexistent_cid,
        }]),
    );
}

#[test]
fn missing_genesis_op() {
    let mut log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_update(|update| update.change_pds("pds.example.com"));

    let genesis = log.remove(0);

    assert_eq!(
        log.audit_log().validate(),
        Err(vec![
            AuditError::GenesisOperationNotCreate,
            AuditError::PrevMissing { prev: genesis.cid },
        ]),
    );
}

#[test]
fn unlinked_first_update() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com").without_prev());

    assert_eq!(
        log.audit_log().validate(),
        Err(vec![AuditError::NonGenesisCreate {
            cid: log.cid_for(1),
        }]),
    );
}

#[test]
fn unlinked_second_update() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_update(|update| update.change_pds("pds.example.com").without_prev());

    assert_eq!(
        log.audit_log().validate(),
        Err(vec![AuditError::NonGenesisCreate {
            cid: log.cid_for(2),
        }]),
    );
}

#[test]
fn order_swapped() {
    let mut log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_update(|update| update.change_pds("pds.example.com"));

    log.swap_in_log(0, 1);

    assert_eq!(
        log.audit_log().validate(),
        Err(vec![
            AuditError::GenesisOperationNotCreate,
            AuditError::PrevReferencesFuture {
                cid: log.cid_for(0),
                prev: log.cid_for(1),
            },
            AuditError::NonGenesisCreate {
                cid: log.cid_for(1),
            },
        ]),
    );
}

#[test]
fn order_reversed() {
    let mut log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_update(|update| update.change_pds("pds.example.com"));

    log.swap_in_chain(0, 1);

    assert_eq!(
        log.audit_log().validate(),
        Err(vec![
            // The DID is now being derived from the wrong operation.
            AuditError::GenesisOperationInvalidDid {
                expected: log.claimed_did(),
                actual: log.did(),
            },
            // Changing the `prev` pointers in each operation altered their CIDs and
            // invalidated their signatures.
            AuditError::EntryCidInvalid {
                cid: log.claimed_cid_for(0),
                actual: log.cid_for(0),
            },
            AuditError::TrustViolation {
                cid: log.claimed_cid_for(0),
            },
            AuditError::EntryCidInvalid {
                cid: log.claimed_cid_for(1),
                actual: log.cid_for(1),
            },
            AuditError::TrustViolation {
                cid: log.claimed_cid_for(1),
            },
            // We only changed the `prev` pointers; their timestamps now have incorrect
            // causality.
            AuditError::EntryCreatedBeforePrev {
                cid: log.claimed_cid_for(1),
                prev: log.claimed_cid_for(0),
            },
            // Currently `TestLog::swap_in_chain` does not swap the `prev` pointers that
            // point *to* the swapped entries, so we now also have a forked chain. This is
            // a limitation of the test kit that I may get around to fixing at some point.
            AuditError::EntryIncorrectlyActive {
                cid: log.claimed_cid_for(1),
            },
        ]),
    );
}

#[test]
fn multiple_active_children() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_update(|update| update.change_pds("pds.example.com").with_prev_op(0));

    assert_eq!(
        log.audit_log().validate(),
        Err(vec![AuditError::MultipleActiveChildren {
            cid: log.cid_for(2),
            first: log.cid_for(1),
        }]),
    );
}

#[test]
fn correctly_nullified() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com").nullified())
        .apply_update(|update| {
            update
                .change_pds("pds.example.com")
                .with_prev_op(0)
                .signed_with_key(0)
        });

    assert_eq!(log.audit_log().validate(), Ok(()));
}

#[test]
fn missing_nullified() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_update(|update| {
            update
                .change_pds("pds.example.com")
                .with_prev_op(0)
                .signed_with_key(0)
        });

    assert_eq!(
        log.audit_log().validate(),
        Err(vec![AuditError::EntryIncorrectlyActive {
            cid: log.cid_for(1),
        }]),
    );
}

#[test]
fn multiple_correctly_nullified() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.rotate_rotation_key(2))
        .apply_update(|update| {
            update
                .change_handle("bob.example.com")
                .signed_with_key(2)
                .nullified()
        })
        .apply_update(|update| {
            update
                .change_handle("carol.example.com")
                .with_prev_op(1)
                .signed_with_key(1)
                .nullified()
        })
        .apply_update(|update| {
            update
                .change_handle("dave.example.com")
                .with_prev_op(1)
                .signed_with_key(0)
        });

    assert_eq!(log.audit_log().validate(), Ok(()));
}

#[test]
fn multiple_incorrectly_nullified() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.rotate_rotation_key(2))
        .apply_update(|update| {
            update
                .change_handle("bob.example.com")
                .signed_with_key(2)
                .nullified()
        })
        .apply_update(|update| {
            update
                .change_handle("carol.example.com")
                .with_prev_op(1)
                .signed_with_key(1)
        })
        .apply_update(|update| {
            update
                .change_handle("dave.example.com")
                .with_prev_op(1)
                .signed_with_key(0)
                .nullified()
        });

    assert_eq!(
        log.audit_log().validate(),
        Err(vec![AuditError::EntryIncorrectlyNullified {
            cid: log.cid_for(4),
        }]),
    );
}

#[test]
fn nullified_with_same_key() {
    let log = TestLog::with_genesis()
        .apply_update(|update| {
            update
                .change_handle("bob.example.com")
                .signed_with_key(0)
                .nullified()
        })
        .apply_update(|update| {
            update
                .change_pds("pds.example.com")
                .with_prev_op(0)
                .signed_with_key(0)
        });

    assert_eq!(
        log.audit_log().validate(),
        Err(vec![
            AuditError::EntryIncorrectlyActive {
                cid: log.cid_for(2),
            },
            AuditError::EntryIncorrectlyNullified {
                cid: log.cid_for(1),
            },
        ]),
    );
}

#[test]
fn nullified_with_active_child() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com").nullified())
        .apply_update(|update| update.change_pds("pds.example.com"));

    assert_eq!(
        log.audit_log().validate(),
        Err(vec![
            AuditError::EntryIncorrectlyActive {
                cid: log.cid_for(2),
            },
            AuditError::EntryIncorrectlyNullified {
                cid: log.cid_for(1),
            },
        ]),
    );
}

#[test]
fn genesis_nullified() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_update(|update| update.change_pds("pds.example.com"));

    let mut audit_log = log.audit_log();
    audit_log.entries[0].nullified = true;

    assert_eq!(
        audit_log.validate(),
        Err(vec![
            AuditError::EntryIncorrectlyNullified {
                cid: log.cid_for(0),
            },
            // The direct child shows up as incorrectly active because the validator
            // observes its parent as nullified. Subsequent children do not generate an
            // error because we don't unnecessarily propagate errors down-chain (the
            // validator has already rejected the log; the errors are just to help the
            // caller determine why).
            AuditError::EntryIncorrectlyActive {
                cid: log.cid_for(1),
            },
        ]),
    );
}

#[test]
fn nullified_in_time() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com").nullified())
        .apply_update(|update| {
            update
                .change_pds("pds.example.com")
                .with_prev_op(0)
                .signed_with_key(0)
                .created_after(1, Duration::seconds(72 * 60 * 60))
        });

    assert_eq!(log.audit_log().validate(), Ok(()));
}

#[test]
fn nullified_late() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com").nullified())
        .apply_update(|update| {
            update
                .change_pds("pds.example.com")
                .with_prev_op(0)
                .signed_with_key(0)
                .created_after(1, Duration::seconds(72 * 60 * 60 + 1))
        });

    assert_eq!(
        log.audit_log().validate(),
        Err(vec![
            AuditError::EntryIncorrectlyActive {
                cid: log.cid_for(2),
            },
            AuditError::EntryIncorrectlyNullified {
                cid: log.cid_for(1),
            },
        ])
    );
}

#[test]
fn valid_tombstone() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_tombstone(|t| t);

    assert_eq!(log.audit_log().validate(), Ok(()));
}

#[test]
fn tombstone_with_padded_sig() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_tombstone(|t| t.padded_sig());

    assert_eq!(
        log.audit_log().validate(),
        Err(vec![AuditError::InvalidSignatureEncoding {
            cid: log.cid_for(2),
        }]),
    );
}

#[test]
fn tombstone_with_invalid_sig() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_tombstone(|t| t.invalid_sig());

    assert_eq!(
        log.audit_log().validate(),
        Err(vec![AuditError::TrustViolation {
            cid: log.cid_for(2),
        }]),
    );
}

#[test]
fn tombstone_signed_with_signing_key() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_tombstone(|t| t.signed_with_signing_key());

    assert_eq!(
        log.audit_log().validate(),
        Err(vec![AuditError::TrustViolation {
            cid: log.cid_for(2),
        }]),
    );
}

#[test]
fn tombstone_signed_with_rotated_key() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_update(|update| update.rotate_rotation_key(0))
        .apply_tombstone(|t| t.signed_with_key_from(2, 0));

    assert_eq!(log.audit_log().validate(), Ok(()));
}

#[test]
fn tombstone_signed_with_old_rotation_key() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_update(|update| update.rotate_rotation_key(0))
        .apply_tombstone(|t| t.signed_with_key_from(1, 0));

    assert_eq!(
        log.audit_log().validate(),
        Err(vec![AuditError::TrustViolation {
            cid: log.cid_for(3),
        }]),
    );
}

#[test]
fn tombstone_with_missing_prev() {
    let nonexistent_cid: Cid = "bafyreiaegzwq2gvetzeaybcqy6f4a7ez6gdocmnz6c4uljh5exhn26oj4u"
        .parse()
        .unwrap();

    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_tombstone(|t| t.with_prev_cid(nonexistent_cid.clone()));

    assert_eq!(
        log.audit_log().validate(),
        Err(vec![AuditError::PrevMissing {
            prev: nonexistent_cid,
        }]),
    );
}

#[test]
fn tombstone_revoking_operation() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_update(|update| update.change_pds("pds.example.com").nullified())
        .apply_tombstone(|t| t.with_prev_op(1).signed_with_key(0));

    assert_eq!(log.audit_log().validate(), Ok(()));
}

#[test]
fn tombstone_revoking_operation_in_time() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_update(|update| update.change_pds("pds.example.com").nullified())
        .apply_tombstone(|t| {
            t.with_prev_op(1)
                .signed_with_key(0)
                .created_after(1, Duration::seconds(72 * 60 * 60))
        });

    assert_eq!(log.audit_log().validate(), Ok(()));
}

#[test]
fn tombstone_revoking_operation_late() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_update(|update| update.change_pds("pds.example.com").nullified())
        .apply_tombstone(|t| {
            t.with_prev_op(1)
                .signed_with_key(0)
                .created_after(1, Duration::seconds(72 * 60 * 60 + 1))
        });

    assert_eq!(
        log.audit_log().validate(),
        Err(vec![
            AuditError::EntryIncorrectlyActive {
                cid: log.cid_for(3),
            },
            AuditError::EntryIncorrectlyNullified {
                cid: log.cid_for(2),
            },
        ])
    );
}

#[test]
fn nullified_tombstone() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_tombstone(|t| t.nullified())
        .apply_update(|update| {
            update
                .change_pds("pds.example.com")
                .with_prev_op(1)
                .signed_with_key(0)
        });

    assert_eq!(log.audit_log().validate(), Ok(()));
}

#[test]
fn unrevokable_tombstone() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_tombstone(|t| t.signed_with_key(0).nullified())
        .apply_update(|update| {
            update
                .change_pds("pds.example.com")
                .with_prev_op(1)
                .signed_with_key(0)
        });

    assert_eq!(
        log.audit_log().validate(),
        Err(vec![
            AuditError::EntryIncorrectlyActive {
                cid: log.cid_for(3),
            },
            AuditError::EntryIncorrectlyNullified {
                cid: log.cid_for(2),
            },
        ])
    );
}

#[test]
fn op_after_tombstone() {
    let log = TestLog::with_genesis()
        .apply_update(|update| update.change_handle("bob.example.com"))
        .apply_tombstone(|t| t)
        .apply_update(|update| update.change_pds("pds.example.com"));

    assert_eq!(
        log.audit_log().validate(),
        Err(vec![AuditError::OperationAfterDeactivation {
            cid: log.cid_for(3),
            prev: log.cid_for(2),
        }]),
    );
}
