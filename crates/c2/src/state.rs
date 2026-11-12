use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chamuko_protocol::{AgentInfo, Task, TaskResult, Timestamp};

#[derive(Debug, Clone)]
pub struct ConsoleLine {
    pub ts: Timestamp,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct AgentEntry {
    pub info: AgentInfo,
    pub last_seen: Timestamp,
    pub sleep: u64,
    pub jitter: u64,
    pub pending: Vec<Task>,
    pub results: Vec<TaskResult>,
    pub console: Vec<ConsoleLine>,
}

impl AgentEntry {
    pub fn new(info: AgentInfo, sleep: u64, jitter: u64) -> Self {
        let mut console = Vec::new();
        console.push(ConsoleLine {
            ts: chamuko_protocol::now_secs(),
            text: format!(
                "agent registered: {}@{} ({}/{})",
                info.username, info.hostname, info.os, info.arch
            ),
        });
        Self {
            info,
            last_seen: chamuko_protocol::now_secs(),
            sleep,
            jitter,
            pending: Vec::new(),
            results: Vec::new(),
            console,
        }
    }

    pub fn push_console(&mut self, text: impl Into<String>) {
        self.console.push(ConsoleLine {
            ts: chamuko_protocol::now_secs(),
            text: text.into(),
        });
    }
}

#[derive(Default)]
pub struct State {
    agents: HashMap<String, AgentEntry>,
    next_agent_id: u64,
    next_task_id: u64,
}

pub type SharedState = Arc<Mutex<State>>;

impl State {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_agent(&mut self, mut info: AgentInfo, sleep: u64, jitter: u64) -> String {
        self.next_agent_id += 1;
        let id = format!("chamuko-{:04}", self.next_agent_id);
        info.id = id.clone();
        let entry = AgentEntry::new(info, sleep, jitter);
        self.agents.insert(id.clone(), entry);
        id
    }

    pub fn get(&self, id: &str) -> Option<&AgentEntry> {
        self.agents.get(id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut AgentEntry> {
        self.agents.get_mut(id)
    }

    pub fn agents(&self) -> impl Iterator<Item = (&String, &AgentEntry)> {
        self.agents.iter()
    }

    pub fn agent_ids(&self) -> Vec<String> {
        self.agents.keys().cloned().collect()
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
        entry.pending.push(task);
        Some(task_id)
    }

    pub fn drain_tasks(&mut self, agent_id: &str) -> Option<Vec<Task>> {
        let entry = self.agents.get_mut(agent_id)?;
        entry.last_seen = chamuko_protocol::now_secs();
        let tasks = std::mem::take(&mut entry.pending);
        Some(tasks)
    }

    pub fn store_results(&mut self, agent_id: &str, results: Vec<TaskResult>) -> Option<()> {
        let entry = self.agents.get_mut(agent_id)?;
        for r in results {
            if let Some(err) = &r.error {
                entry.push_console(format!("err [{}]: {}", r.task_id, err));
            } else {
                entry.push_console(format!("out [{}]:\n{}", r.task_id, r.output));
            }
            entry.results.push(r);
        }
        Some(())
    }
}
