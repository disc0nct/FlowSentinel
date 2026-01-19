use super::app::App;
use super::widgets;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Frame,
};

pub struct Dashboard;

impl Dashboard {
    pub fn draw(frame: &mut Frame, app: &App) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Min(10),   // Main table
                Constraint::Length(3), // Status bar
            ])
            .split(frame.area());

        Self::draw_header(frame, chunks[0], app);
        Self::draw_table(frame, chunks[1], app);
        Self::draw_status_bar(frame, chunks[2], app);
    }

    fn draw_header(frame: &mut Frame, area: Rect, app: &App) {
        let total_bytes = app.processes.iter().map(|p| p.bytes_per_sec).sum::<f64>();
        let total_conns: usize = app.processes.iter().map(|p| p.connection_count).sum();

        let header_text = vec![
            Span::styled("FlowSentinel", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(" | "),
            Span::styled(format!("Processes: {}", app.processes.len()), Style::default().fg(Color::Green)),
            Span::raw(" | "),
            Span::styled(format!("Total: {}/s", widgets::format_bytes(total_bytes as u64)), Style::default().fg(Color::Yellow)),
            Span::raw(" | "),
            Span::styled(format!("Connections: {}", total_conns), Style::default().fg(Color::Magenta)),
            if app.paused {
                Span::styled(" [PAUSED]", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
            } else {
                Span::raw("")
            },
            if app.follow_mode {
                Span::styled(" [FOLLOW]", Style::default().fg(Color::Blue))
            } else {
                Span::raw("")
            },
        ];

        let header = Paragraph::new(Line::from(header_text))
            .block(Block::default().borders(Borders::ALL).title("Network Traffic Monitor"));

        frame.render_widget(header, area);
    }

    fn draw_table(frame: &mut Frame, area: Rect, app: &App) {
        let header_cells = [
            "Name",
            "PID",
            "UID",
            "Bytes/s",
            "Pkts/s",
            "Conns",
            "Last DNS",
        ]
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let style = if matches!(
                (&app.sort_column, i),
                (super::app::SortColumn::Name, 0)
                    | (super::app::SortColumn::Pid, 1)
                    | (super::app::SortColumn::BytesPerSec, 3)
                    | (super::app::SortColumn::PacketsPerSec, 4)
                    | (super::app::SortColumn::Connections, 5)
            ) {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            Cell::from(*h).style(style)
        });

        let header = Row::new(header_cells)
            .style(Style::default().add_modifier(Modifier::BOLD))
            .height(1);

        let rows = app.processes.iter().enumerate().map(|(i, process)| {
            let style = if i == app.selected_index {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else if i % 2 == 0 {
                Style::default()
            } else {
                Style::default().bg(Color::Rgb(30, 30, 30))
            };

            let bytes_color = if process.bytes_per_sec > 1_000_000.0 {
                Color::Red
            } else if process.bytes_per_sec > 100_000.0 {
                Color::Yellow
            } else if process.bytes_per_sec > 0.0 {
                Color::Green
            } else {
                Color::Gray
            };
            
            // Colorize name based on UID (Root = LightRed, User = LightGreen)
            let name_color = if process.uid == 0 {
                Color::LightRed
            } else {
                Color::LightGreen
            };

            let last_dns = process.dns_queries.last().map(|s| s.query.as_str()).unwrap_or("");

            let name_display = if process.is_recording {
                format!("{} [REC]", truncate_str(&process.name, 20))
            } else {
                truncate_str(&process.name, 25)
            };

            Row::new(vec![
                Cell::from(name_display).style(Style::default().fg(name_color)),
                Cell::from(process.pid.to_string()),
                Cell::from(process.uid.to_string()),
                Cell::from(format!("{}/s", widgets::format_bytes(process.bytes_per_sec as u64)))
                    .style(Style::default().fg(bytes_color)),
                Cell::from(format!("{:.0}", process.packets_per_sec)),
                Cell::from(process.connection_count.to_string()),
                // Don't truncate DNS, let the table widget handle it so it fills available space
                Cell::from(last_dns).style(Style::default().fg(Color::Cyan)),
            ])
            .style(style)
            .height(1)
        });

        let widths = if app.compact_mode {
            vec![
                Constraint::Length(15), // Name
                Constraint::Length(7),  // PID
                Constraint::Length(5),  // UID
                Constraint::Length(10), // Bytes/s
                Constraint::Length(6),  // Pkts/s
                Constraint::Length(5),  // Conns
                Constraint::Min(20),    // Last DNS
            ]
        } else {
            vec![
                Constraint::Length(20), // Name
                Constraint::Length(8),  // PID
                Constraint::Length(6),  // UID
                Constraint::Length(12), // Bytes/s
                Constraint::Length(8),  // Pkts/s
                Constraint::Length(6),  // Conns
                Constraint::Min(30),    // Last DNS
            ]
        };

        let table = Table::new(rows, widths)
            .header(header)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" Processes (Sort: {} {}) ",
                        app.sort_column.label(),
                        if app.sort_ascending { "▲" } else { "▼" }
                    )),
            )
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

        let mut state = TableState::default();
        state.select(Some(app.selected_index));

        frame.render_stateful_widget(table, area, &mut state);
    }

    fn draw_status_bar(frame: &mut Frame, area: Rect, app: &App) {
        let filter_display = if app.filter_active {
            format!("Filter: {}█", app.filter_input)
        } else if !app.filter_input.is_empty() {
            format!("Filter: {}", app.filter_input)
        } else {
            String::new()
        };

        let help_text = if app.filter_active {
            "Enter: Apply | Esc: Cancel"
        } else {
            "/: Filter | Enter: Details | x: Kill | s: Sort | f: Follow | ?: Help | q: Quit"
        };

        let status_spans = vec![
            Span::styled(
                if !app.status_message.is_empty() {
                    format!(" {} ", app.status_message)
                } else if !filter_display.is_empty() {
                    format!(" {} ", filter_display)
                } else {
                    String::new()
                },
                Style::default().fg(Color::Cyan),
            ),
            Span::raw(" "),
            Span::styled(help_text, Style::default().fg(Color::DarkGray)),
        ];

        let status_bar = Paragraph::new(Line::from(status_spans))
            .block(Block::default().borders(Borders::ALL));

        frame.render_widget(status_bar, area);
    }
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    } else {
        s.to_string()
    }
}
