use atrium_api::types::string::Did;

use super::LogEntry;

#[derive(Debug)]
pub(crate) struct AuditLog {
    did: Did,
    entries: Vec<LogEntry>,
}

impl AuditLog {
    pub(super) fn new(did: Did, entries: Vec<LogEntry>) -> Self {
        Self { did, entries }
    }
}
