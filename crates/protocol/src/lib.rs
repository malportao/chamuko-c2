//! Shared wire types exchanged between a Chamuko agent and its C2 server.
//!
//! All messages are serialized as JSON over HTTP(S). The design keeps the
//! surface small so that custom transports can be added later without
//! touching the agent logic.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Seconds since the Unix epoch, used for ordering beacons and task results.
pub type Timestamp = u64;

pub fn now_secs() -> Timestamp {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Metadata describing the host an agent is running on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentInfo {
    /// Server-assigned identifier; empty until registration completes.
    #[serde(default)]
    pub id: String,
    /// Optional operator-chosen label for the agent.
    #[serde(default)]
    pub name: String,
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub arch: String,
    pub pid: u32,
    pub ip: String,
}

impl AgentInfo {
    /// Collect local host metadata at runtime. The `id` is left empty and
    /// assigned by the C2 on first registration.
    pub fn local(name: String) -> Self {
        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| "unknown".to_string());
        let username = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "unknown".to_string());
        let pid = std::process::id();
        let os = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();
        Self {
            id: String::new(),
            name,
            hostname,
            username,
            os,
            arch,
            pid,
            ip: String::new(),
        }
    }
}

/// Body posted by the agent to `/register`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub agent: AgentInfo,
}

/// Response returned by the C2 after a successful registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    /// The unique identifier the agent must use in all subsequent beacons.
    pub id: String,
    /// Base sleep interval between beacons, in seconds.
    #[serde(default = "default_sleep")]
    pub sleep: u64,
    /// Maximum random jitter added to the sleep, in seconds.
    #[serde(default)]
    pub jitter: u64,
}

fn default_sleep() -> u64 {
    10
}

/// Body posted by the agent on every beacon to `/beacon`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconRequest {
    pub id: String,
    #[serde(default = "now_secs")]
    pub timestamp: Timestamp,
}

/// A single command dispatched to an agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Task {
    pub id: String,
    /// Plugin command name, e.g. `"exec"`, `"info"`, `"sleep"`.
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
}

/// Response to a beacon; carries any pending tasks for the agent.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BeaconResponse {
    #[serde(default)]
    pub tasks: Vec<Task>,
}

/// Outcome of a single task execution on the agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskResult {
    pub task_id: String,
    #[serde(default)]
    pub output: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

/// Body posted by the agent to `/results`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResultsRequest {
    pub id: String,
    #[serde(default)]
    pub results: Vec<TaskResult>,
}
