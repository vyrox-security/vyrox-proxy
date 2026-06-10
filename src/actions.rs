use serde::{Deserialize, Serialize};

/// A containment action the proxy can apply to a host.
///
/// Each variant has a natural inverse (un-isolate, restore network). The
/// inverse is not a separate `ActionType`: the SAME action type is carried
/// on both `/execute` and `/rollback`, and the `ActionDirection` decides
/// whether we apply or reverse it. This keeps the audit trail honest, a
/// rollback row records the same `action_type` it is reversing, tagged as a
/// rollback, rather than inventing a parallel set of "UN_" actions.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActionType {
    HostIsolation,
    ProcessKill,
    NetworkQuarantine,
}

/// Whether a request applies an action or reverses it.
///
/// `/execute` always applies (`Apply`); `/rollback` always reverses
/// (`Reverse`). The EDR client maps the pair `(ActionType, ActionDirection)`
/// to the concrete vendor call (contain vs lift_containment for CrowdStrike,
/// disconnect vs connect for SentinelOne).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionDirection {
    /// Apply the action (isolate the host, quarantine the network).
    Apply,
    /// Reverse the action (un-isolate, restore the network).
    Reverse,
}
