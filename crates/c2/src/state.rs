use std::collections::HashMap;

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

impl State {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_agent(&mut self, mut info: AgentInfo, sleep: u64, jitter: u64) -> String {
        self.next_agent_id += 1;
        let id = format!("chamuko-{:04}", self.next_agent_id);
        info.id = id.clone();
        self.agents.insert(id.clone(), AgentEntry::new(info, sleep, jitter));
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
        entry.pending.push(task);
        Some(task_id)
    }

    /// Returns the queued tasks plus the beacon interval the agent should adopt.
    pub fn drain_tasks(&mut self, agent_id: &str) -> Option<(Vec<Task>, u64, u64)> {
        let entry = self.agents.get_mut(agent_id)?;
        entry.last_seen = chamuko_protocol::now_secs();
        let tasks = std::mem::take(&mut entry.pending);
        Some((tasks, entry.sleep, entry.jitter))
    }

    pub fn store_results(&mut self, agent_id: &str, results: Vec<TaskResult>) -> Option<()> {
        let entry = self.agents.get_mut(agent_id)?;
        entry.last_seen = chamuko_protocol::now_secs();
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

    #[test]
    fn assigns_sequential_agent_ids() {
        let mut state = State::new();
        assert_eq!(state.register_agent(info("a"), 5, 2), "chamuko-0001");
        assert_eq!(state.register_agent(info("b"), 5, 2), "chamuko-0002");
        assert_eq!(state.agent_ids(), vec!["chamuko-0001", "chamuko-0002"]);
    }

    #[test]
    fn enqueue_and_drain_round_trip_reports_beacon_interval() {
        let mut state = State::new();
        let id = state.register_agent(info("a"), 7, 3);

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
    fn results_are_appended_to_console() {
        let mut state = State::new();
        let id = state.register_agent(info("a"), 5, 2);
        state.store_results(
            &id,
            vec![chamuko_protocol::TaskResult {
                task_id: "task-000001".to_string(),
                output: "ok".to_string(),
                error: None,
                exit_code: Some(0),
            }],
        );
        let entry = state.get(&id).unwrap();
        assert!(entry.console.iter().any(|l| l.text.contains("ok")));
        assert_eq!(entry.results.len(), 1);
    }
}
