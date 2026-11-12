use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
        let command = head.to_string();
        let args: Vec<String> = rest
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        let mut s = self.state.lock().unwrap();
        if s.enqueue_task(&id, command, args).is_none() {
            drop(s);
            self.local_log("failed to enqueue task");
        }
    }

    fn local_log(&mut self, text: impl Into<String>) {
        if let Some(id) = self.selected_agent() {
            let mut s = self.state.lock().unwrap();
            if let Some(entry) = s.get_mut(&id) {
                entry.push_console(text);
            }
        }
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

    let input = Paragraph::new(app.input.as_str())
        .style(Style::default().fg(BRIGHT).bg(BLACK))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(DARK_RED))
                .style(Style::default().bg(BLACK))
                .title(Span::styled(
                    " command ",
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
                    .skip(app.console_scroll)
                    .map(|l| Line::from(l.text.clone()))
                    .collect(),
                None => vec![Line::from("agent not found")],
            }
        }
        None => vec![Line::from(Span::styled(
            "no agent selected — use 'list' and 'use <id>'",
            Style::default().fg(GREY),
        ))],
    };

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

    f.render_widget(para, area);
}
