use super::dashboard::Dashboard;
use super::detail::DetailView;
use super::help::HelpOverlay;
use super::kill::KillOverlay;
use super::whois::WhoisOverlay;
use crate::collector::ProcessMetrics;
use crate::cli::Cli;
use crate::store::Store;
use crate::filter;
use crate::export;
use crossterm::event::{KeyCode, KeyEvent};
use parking_lot::RwLock;
use ratatui::Frame;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum View {
    Dashboard,
    ProcessDetail,
    Help,
    KillConfirm,
    Whois,
}

pub enum KeyAction {
    Continue,
    Quit,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SortColumn {
    Name,
    Pid,
    BytesPerSec,
    PacketsPerSec,
    Connections,
}

impl SortColumn {
    pub fn label(&self) -> &str {
        match self {
            SortColumn::Name => "Name",
            SortColumn::Pid => "PID",
            SortColumn::BytesPerSec => "Traffic",
            SortColumn::PacketsPerSec => "Packets",
            SortColumn::Connections => "Connections",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            SortColumn::BytesPerSec => SortColumn::Pid,
            SortColumn::Pid => SortColumn::Name,
            SortColumn::Name => SortColumn::Connections,
            SortColumn::Connections => SortColumn::PacketsPerSec,
            SortColumn::PacketsPerSec => SortColumn::BytesPerSec,
        }
    }
}

pub struct App {
    store: Arc<RwLock<Store>>,
    cli: Cli,
    pub view: View,
    pub processes: Vec<ProcessMetrics>,
    pub selected_index: usize,
    pub selected_process: Option<ProcessMetrics>,
    pub sort_column: SortColumn,
    pub sort_ascending: bool,
    pub filter_input: String,
    pub filter_active: bool,
    pub detail_filter_input: String,
    pub detail_filter_active: bool,
    pub paused: bool,
    pub follow_mode: bool,
    pub compact_mode: bool,
    pub selected_connection_index: usize,
    pub selected_query_index: usize,
    pub detail_scroll_focus: DetailFocus,
    pub dns_autoscroll: bool,
    pub status_message: String,
    pub whois_result: Option<String>,
    pub whois_rx: std::sync::mpsc::Receiver<String>,
    whois_tx: std::sync::mpsc::Sender<String>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DetailFocus {
    Connections,
    Queries,
}

impl App {
    pub fn new(store: Arc<RwLock<Store>>, cli: Cli) -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        Self {
            store,
            follow_mode: cli.follow,
            cli,
            view: View::Dashboard,
            processes: Vec::new(),
            selected_index: 0,
            selected_process: None,
            sort_column: SortColumn::BytesPerSec,
            sort_ascending: false,
            filter_input: String::new(),
            filter_active: false,
            detail_filter_input: String::new(),
            detail_filter_active: false,
            paused: false,
            compact_mode: false,
            selected_connection_index: 0,
            selected_query_index: 0,
            detail_scroll_focus: DetailFocus::Connections,
            dns_autoscroll: true,
            status_message: String::new(),
            whois_result: None,
            whois_rx: rx,
            whois_tx: tx,
        }
    }

    pub async fn update(&mut self) {
        // Check for WHOIS results
        if let Ok(res) = self.whois_rx.try_recv() {
            self.whois_result = Some(res);
        }

        if self.paused {
            return;
        }

        let store = self.store.read();
        let mut processes = store.get_all_processes();
        drop(store);

        // Apply CLI filter
        if let Some(ref filter) = self.cli.filter {
            let parsed = filter::parse_filter(filter);
            processes.retain(|p| filter::matches_process(p, &parsed));
        }

        // Apply interactive filter
        if !self.filter_input.is_empty() {
            let parsed = filter::parse_filter(&self.filter_input);
            processes.retain(|p| filter::matches_process(p, &parsed));
        }

        // Apply PID filter from CLI
        if let Some(pid) = self.cli.pid {
            processes.retain(|p| p.pid == pid);
        }

        // Sort
        self.sort_processes(&mut processes);

        // Apply top limit
        if let Some(n) = self.cli.top {
            processes.truncate(n);
        }

        self.processes = processes;

        // Update selected process for detail view
        if let Some(ref current) = self.selected_process {
            self.selected_process = self.processes.iter().find(|p| p.pid == current.pid).cloned();
            
            // Handle DNS autoscroll
            if self.dns_autoscroll {
                if let Some(ref p) = self.selected_process {
                    if !p.dns_queries.is_empty() {
                        self.selected_query_index = p.dns_queries.len().saturating_sub(1);
                    }
                }
            }
        }

        // Follow mode: keep focus on top
        if self.follow_mode && !self.processes.is_empty() {
            self.selected_index = 0;
        }
    }

    fn sort_processes(&self, processes: &mut [ProcessMetrics]) {
        match self.sort_column {
            SortColumn::Name => {
                processes.sort_by(|a, b| {
                    if self.sort_ascending {
                        a.name.cmp(&b.name)
                    } else {
                        b.name.cmp(&a.name)
                    }
                });
            }
            SortColumn::Pid => {
                processes.sort_by(|a, b| {
                    if self.sort_ascending {
                        a.pid.cmp(&b.pid)
                    } else {
                        b.pid.cmp(&a.pid)
                    }
                });
            }
            SortColumn::BytesPerSec => {
                processes.sort_by(|a, b| {
                    if self.sort_ascending {
                        a.bytes_per_sec.total_cmp(&b.bytes_per_sec)
                    } else {
                        b.bytes_per_sec.total_cmp(&a.bytes_per_sec)
                    }
                });
            }
            SortColumn::PacketsPerSec => {
                processes.sort_by(|a, b| {
                    if self.sort_ascending {
                        a.packets_per_sec.total_cmp(&b.packets_per_sec)
                    } else {
                        b.packets_per_sec.total_cmp(&a.packets_per_sec)
                    }
                });
            }
            SortColumn::Connections => {
                processes.sort_by(|a, b| {
                    if self.sort_ascending {
                        a.connection_count.cmp(&b.connection_count)
                    } else {
                        b.connection_count.cmp(&a.connection_count)
                    }
                });
            }
        }
    }

    pub fn draw(&self, frame: &mut Frame) {
        match self.view {
            View::Dashboard => Dashboard::draw(frame, self),
            View::ProcessDetail => DetailView::draw(frame, self),
            View::Help => {
                Dashboard::draw(frame, self);
                HelpOverlay::draw(frame);
            }
            View::KillConfirm => {
                Dashboard::draw(frame, self);
                KillOverlay::draw(frame, self);
            }
            View::Whois => {
                DetailView::draw(frame, self);
                WhoisOverlay::draw(frame, self);
            }
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> KeyAction {
        // Filter input mode
        if self.filter_active {
            return self.handle_filter_input(key);
        }
        if self.detail_filter_active {
            return self.handle_detail_filter_input(key);
        }

        match self.view {
            View::Help => {
                // Any key exits help
                self.view = View::Dashboard;
                KeyAction::Continue
            }
            View::KillConfirm => self.handle_kill_confirm(key),
            View::Whois => {
                if key.code == KeyCode::Esc || key.code == KeyCode::Char('q') {
                    self.view = View::ProcessDetail;
                    self.whois_result = None;
                }
                KeyAction::Continue
            }
            View::ProcessDetail => self.handle_detail_key(key),
            View::Dashboard => self.handle_dashboard_key(key),
        }
    }

    pub fn handle_mouse(&mut self, mouse: crossterm::event::MouseEvent) -> KeyAction {
        match mouse.kind {
            crossterm::event::MouseEventKind::ScrollDown => {
                match self.view {
                    View::Dashboard => {
                        if self.selected_index < self.processes.len().saturating_sub(1) {
                            self.selected_index += 1;
                        }
                    }
                    View::ProcessDetail => {
                         if let Some(ref p) = self.selected_process {
                            match self.detail_scroll_focus {
                                DetailFocus::Connections => {
                                    if self.selected_connection_index < p.connections.len().saturating_sub(1) {
                                        self.selected_connection_index += 1;
                                    }
                                }
                                DetailFocus::Queries => {
                                    if self.selected_query_index < p.dns_queries.len().saturating_sub(1) {
                                        self.selected_query_index += 1;
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            crossterm::event::MouseEventKind::ScrollUp => {
                match self.view {
                    View::Dashboard => {
                        self.selected_index = self.selected_index.saturating_sub(1);
                    }
                    View::ProcessDetail => {
                        match self.detail_scroll_focus {
                            DetailFocus::Connections => {
                                self.selected_connection_index = self.selected_connection_index.saturating_sub(1);
                            }
                            DetailFocus::Queries => {
                                self.selected_query_index = self.selected_query_index.saturating_sub(1);
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        KeyAction::Continue
    }

    fn handle_kill_confirm(&mut self, key: KeyEvent) -> KeyAction {
        match key.code {
            KeyCode::Char('y') | KeyCode::Enter => {
                if let Some(ref p) = self.selected_process {
                    // Kill process
                    self.kill_process(p.pid);
                    self.status_message = format!("Sent SIGTERM to PID {}", p.pid);
                }
                self.view = View::Dashboard;
            }
            KeyCode::Char('n') | KeyCode::Esc | KeyCode::Char('q') => {
                self.view = View::Dashboard;
                self.status_message = "Kill cancelled".to_string();
            }
            _ => {}
        }
        KeyAction::Continue
    }

    fn kill_process(&self, pid: u32) {
        #[cfg(unix)]
        {
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
        }
    }

    fn run_whois(&self, ip: String) {
        let tx = self.whois_tx.clone();
        std::thread::spawn(move || {
            let output = std::process::Command::new("whois").arg(&ip).output();
            let result = match output {
                Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
                Err(e) => format!("Error running whois: {}", e),
            };
            let _ = tx.send(result);
        });
    }

    fn handle_filter_input(&mut self, key: KeyEvent) -> KeyAction {
        match key.code {
            KeyCode::Esc => {
                self.filter_active = false;
            }
            KeyCode::Enter => {
                self.filter_active = false;
                self.status_message = format!("Filter: {}", self.filter_input);
            }
            KeyCode::Backspace => {
                self.filter_input.pop();
            }
            KeyCode::Char(c) => {
                self.filter_input.push(c);
            }
            _ => {}
        }
        KeyAction::Continue
    }

    fn handle_detail_filter_input(&mut self, key: KeyEvent) -> KeyAction {
        match key.code {
            KeyCode::Esc => {
                self.detail_filter_active = false;
            }
            KeyCode::Enter => {
                self.detail_filter_active = false;
            }
            KeyCode::Backspace => {
                self.detail_filter_input.pop();
            }
            KeyCode::Char(c) => {
                self.detail_filter_input.push(c);
            }
            _ => {}
        }
        KeyAction::Continue
    }

    fn handle_dashboard_key(&mut self, key: KeyEvent) -> KeyAction {
        match key.code {
            KeyCode::Char('q') => KeyAction::Quit,
            KeyCode::Char('?') => {
                self.view = View::Help;
                KeyAction::Continue
            }
            KeyCode::Char('j') | KeyCode::Down => {
                if self.selected_index < self.processes.len().saturating_sub(1) {
                    self.selected_index += 1;
                }
                KeyAction::Continue
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.selected_index = self.selected_index.saturating_sub(1);
                KeyAction::Continue
            }
            KeyCode::Char('x') => {
                if let Some(process) = self.processes.get(self.selected_index) {
                    self.selected_process = Some(process.clone());
                    self.view = View::KillConfirm;
                }
                KeyAction::Continue
            }
            KeyCode::Char('R') => {
                if let Some(p) = self.processes.get(self.selected_index) {
                    let mut store = self.store.write();
                    if p.is_recording {
                        store.stop_recording(p.pid);
                        self.status_message = format!("Stopped recording PID {}", p.pid);
                    } else {
                        match store.start_recording(p.pid, &p.name) {
                            Ok(file) => self.status_message = format!("Recording to {}", file),
                            Err(e) => self.status_message = format!("Failed to start recording: {}", e),
                        }
                    }
                }
                KeyAction::Continue
            }
            KeyCode::Char('g') => {
                self.selected_index = 0;
                KeyAction::Continue
            }
            KeyCode::Char('G') => {
                if !self.processes.is_empty() {
                    self.selected_index = self.processes.len() - 1;
                }
                KeyAction::Continue
            }
            KeyCode::Enter => {
                if let Some(process) = self.processes.get(self.selected_index) {
                    self.selected_process = Some(process.clone());
                    self.selected_connection_index = 0;
                    self.selected_query_index = 0;
                    self.detail_scroll_focus = DetailFocus::Connections;
                    self.view = View::ProcessDetail;
                }
                KeyAction::Continue
            }
            KeyCode::Char('/') => {
                self.filter_active = true;
                KeyAction::Continue
            }
            KeyCode::Char('s') => {
                self.sort_column = self.sort_column.next();
                self.status_message = format!("Sort by: {}", self.sort_column.label());
                KeyAction::Continue
            }
            KeyCode::Char('S') => {
                self.sort_ascending = !self.sort_ascending;
                let dir = if self.sort_ascending { "ascending" } else { "descending" };
                self.status_message = format!("Sort: {}", dir);
                KeyAction::Continue
            }
            KeyCode::Char('r') => {
                self.paused = !self.paused;
                self.status_message = if self.paused {
                    "Paused".to_string()
                } else {
                    "Resumed".to_string()
                };
                KeyAction::Continue
            }
            KeyCode::Char('f') => {
                self.follow_mode = !self.follow_mode;
                self.status_message = if self.follow_mode {
                    "Follow mode: ON".to_string()
                } else {
                    "Follow mode: OFF".to_string()
                };
                KeyAction::Continue
            }
            KeyCode::Char('c') => {
                self.compact_mode = !self.compact_mode;
                KeyAction::Continue
            }
            KeyCode::Char('e') => {
                // Export current view
                if let Ok(json) = export::to_json(&self.processes) {
                    let filename = format!("flowsentinel_export_{}.json", chrono::Utc::now().format("%Y%m%d_%H%M%S"));
                    if std::fs::write(&filename, json).is_ok() {
                        self.status_message = format!("Exported to {}", filename);
                    } else {
                        self.status_message = "Export failed".to_string();
                    }
                }
                KeyAction::Continue
            }
            KeyCode::Esc => {
                self.filter_input.clear();
                self.status_message.clear();
                KeyAction::Continue
            }
            _ => KeyAction::Continue,
        }
    }

    fn handle_detail_key(&mut self, key: KeyEvent) -> KeyAction {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc | KeyCode::Backspace => {
                self.view = View::Dashboard;
                KeyAction::Continue
            }
            KeyCode::Tab => {
                self.detail_scroll_focus = match self.detail_scroll_focus {
                    DetailFocus::Connections => DetailFocus::Queries,
                    DetailFocus::Queries => DetailFocus::Connections,
                };
                self.status_message = format!("Focus: {:?}", self.detail_scroll_focus);
                KeyAction::Continue
            }
            KeyCode::Char('?') => {
                self.view = View::Help;
                KeyAction::Continue
            }
            KeyCode::Char('a') => {
                self.dns_autoscroll = !self.dns_autoscroll;
                self.status_message = format!("DNS Autoscroll: {}", if self.dns_autoscroll { "ON" } else { "OFF" });
                KeyAction::Continue
            }
            KeyCode::Char('/') => {
                self.detail_filter_active = true;
                KeyAction::Continue
            }
            KeyCode::Char('j') | KeyCode::Down => {
                if let Some(ref p) = self.selected_process {
                    match self.detail_scroll_focus {
                        DetailFocus::Connections => {
                            if self.selected_connection_index < p.connections.len().saturating_sub(1) {
                                self.selected_connection_index += 1;
                            }
                        }
                        DetailFocus::Queries => {
                            if self.selected_query_index < p.dns_queries.len().saturating_sub(1) {
                                self.selected_query_index += 1;
                            }
                        }
                    }
                }
                KeyAction::Continue
            }
            KeyCode::Char('k') | KeyCode::Up => {
                match self.detail_scroll_focus {
                    DetailFocus::Connections => {
                        self.selected_connection_index = self.selected_connection_index.saturating_sub(1);
                    }
                    DetailFocus::Queries => {
                        self.selected_query_index = self.selected_query_index.saturating_sub(1);
                    }
                }
                KeyAction::Continue
            }
            KeyCode::Char('w') => {
                if let Some(ref p) = self.selected_process {
                    if let Some(conn) = p.connections.get(self.selected_connection_index) {
                        let ip = conn.remote_addr.clone();
                        if ip != "0.0.0.0" && ip != "::" && ip != "127.0.0.1" {
                            self.run_whois(ip);
                            self.view = View::Whois;
                        } else {
                            self.status_message = "Cannot run WHOIS on local address".to_string();
                        }
                    }
                }
                KeyAction::Continue
            }
            _ => KeyAction::Continue,
        }
    }
}
