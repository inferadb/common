//! Retry logic for CAS (compare-and-set) conflict resolution.
//!
//! This module re-exports [`with_cas_retry`] from the base storage crate
//! for internal use within the ledger backend.

pub(crate) use inferadb_common_storage::with_cas_retry;
