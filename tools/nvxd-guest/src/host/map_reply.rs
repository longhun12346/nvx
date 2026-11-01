//! How the guest agent answers a part of the host's mapping table, which
//! [`Client::map`](super::Client::map) returns: a [`MapReply`].

use crate::root::MapFailure;

/// How the guest agent answered a part of the host's mapping table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MapReply {
    /// `Mapped`: it applied the part's mappings.
    Mapped,
    /// `MapFailed`: it refused the part, or failed to apply one of its mappings, after which it
    /// refuses the rest of the table and the start.
    Failed(MapFailure),
}
