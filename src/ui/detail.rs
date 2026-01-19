use super::app::App;
use super::widgets;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap, Sparkline},
    Frame,
};

pub struct DetailView;

impl DetailView {
    pub fn draw(frame: &mut Frame, app: &App) {
        if let Some(ref process) = app.selected_process {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Length(10),  // Process info & Graph
                    Constraint::Min(10),    // Connections table
                    Constraint::Length(10), // DNS queries
                    Constraint::Length(3),  // Status bar
                ])
                .split(frame.area());

            Self::draw_process_info(frame, chunks[0], process);
            Self::draw_connections(frame, chunks[1], process, app.selected_connection_index, app.detail_scroll_focus == crate::ui::app::DetailFocus::Connections, &app.detail_filter_input);
            Self::draw_dns_queries(frame, chunks[2], process, app.selected_query_index, app.detail_scroll_focus == crate::ui::app::DetailFocus::Queries, &app.detail_filter_input, app.dns_autoscroll);
            Self::draw_status_bar(frame, chunks[3], app);
        } else {
             let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(0),
                ])
                .split(frame.area());

            let msg = Paragraph::new("No process selected")
                .block(Block::default().borders(Borders::ALL).title("Process Details"));
            frame.render_widget(msg, chunks[0]);
            Self::draw_status_bar(frame, chunks[1], app);
        }
    }

    fn draw_dns_queries(frame: &mut Frame, area: Rect, process: &crate::collector::ProcessMetrics, selected_index: usize, is_focused: bool, filter: &str, autoscroll: bool) {
        let autoscroll_status = if autoscroll { " [AUTOSCROLL: ON] " } else { " [AUTOSCROLL: OFF] " };
        let title = if is_focused { 
            format!(" DNS Queries [FOCUS]{} ", autoscroll_status)
        } else { 
            format!(" DNS Queries{} ", autoscroll_status)
        };
        let border_color = if is_focused { Color::Yellow } else { Color::Gray };

        let filtered_queries: Vec<_> = process.dns_queries.iter().filter(|q| {
            filter.is_empty() || q.query.to_lowercase().contains(&filter.to_lowercase())
        }).collect();

        let selected_index = if filtered_queries.is_empty() { 0 } else { selected_index.min(filtered_queries.len() - 1) };

        let queries: Vec<Line> = filtered_queries.iter().enumerate().map(|(i, q)| {
            let style = if is_focused && i == selected_index {
                Style::default().bg(Color::White).fg(Color::Black)
            } else {
                Style::default()
            };
            
            Line::from(vec![
                Span::styled(format!("[{}] ", q.timestamp.format("%H:%M:%S")), Style::default().fg(Color::DarkGray)),
                Span::styled("Query: ", Style::default().fg(Color::Gray)),
                Span::styled(&q.query, Style::default().fg(Color::Yellow)),
            ]).style(style)
        }).collect();

        let mut scroll = 0;
        if is_focused && queries.len() > 8 {
            scroll = selected_index.saturating_sub(4) as u16;
        }

        let block = Paragraph::new(queries)
            .block(Block::default().borders(Borders::ALL).title(title).border_style(Style::default().fg(border_color)))
            .scroll((scroll, 0))
            .wrap(Wrap { trim: true });
        frame.render_widget(block, area);
    }

    fn draw_process_info(frame: &mut Frame, area: Rect, process: &crate::collector::ProcessMetrics) {
        let info_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);

        // Left side - basic info + Parent
        let left_text = vec![
            Line::from(vec![
                Span::styled("PID: ", Style::default().fg(Color::Gray)),
                Span::styled(process.pid.to_string(), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                Span::styled("  PPID: ", Style::default().fg(Color::Gray)),
                Span::styled(process.ppid.map(|p| p.to_string()).unwrap_or_else(|| "N/A".to_string()), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Name: ", Style::default().fg(Color::Gray)),
                Span::styled(&process.name, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("Cmd: ", Style::default().fg(Color::Gray)),
                Span::styled(process.cmdline.as_deref().unwrap_or("N/A"), Style::default().fg(Color::DarkGray)),
            ]),
            Line::from(vec![
                Span::styled("UID: ", Style::default().fg(Color::Gray)),
                Span::styled(process.uid.to_string(), Style::default().fg(Color::White)),
                Span::styled("  Container: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    process.container_id.clone().unwrap_or_else(|| "Host".to_string()), 
                    Style::default().fg(if process.container_id.is_some() { Color::Blue } else { Color::DarkGray })
                ),
            ]),
            Line::from(vec![
                Span::styled("Protocol Distribution: ", Style::default().fg(Color::Gray)),
            ]),
            Line::from(vec![
                Span::styled("TCP: ", Style::default().fg(Color::Blue)),
                Span::styled(widgets::format_bytes(process.protocol_stats.tcp_bytes), Style::default()),
                Span::styled(" UDP: ", Style::default().fg(Color::Yellow)),
                Span::styled(widgets::format_bytes(process.protocol_stats.udp_bytes), Style::default()),
                Span::styled(" ICMP: ", Style::default().fg(Color::Red)),
                Span::styled(widgets::format_bytes(process.protocol_stats.icmp_bytes), Style::default()),
            ]),
        ];

        let left_para = Paragraph::new(left_text)
            .block(Block::default().borders(Borders::ALL).title(" Process Info "))
            .wrap(Wrap { trim: true });

        frame.render_widget(left_para, info_chunks[0]);

        // Right side - traffic stats & Graph
        let right_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(4), Constraint::Min(0)])
            .split(info_chunks[1]);

        let right_text = vec![
            Line::from(vec![
                Span::styled("Bytes/sec: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format!("{}/s", widgets::format_bytes(process.bytes_per_sec as u64)),
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("Packets/sec: ", Style::default().fg(Color::Gray)),
                Span::styled(format!("{:.1}", process.packets_per_sec), Style::default().fg(Color::Yellow)),
            ]),
            Line::from(vec![
                Span::styled("Total In: ", Style::default().fg(Color::Gray)),
                Span::styled(widgets::format_bytes(process.bytes_in), Style::default().fg(Color::Cyan)),
            ]),
            Line::from(vec![
                Span::styled("Total Out: ", Style::default().fg(Color::Gray)),
                Span::styled(widgets::format_bytes(process.bytes_out), Style::default().fg(Color::Magenta)),
            ]),
        ];

        let right_para = Paragraph::new(right_text)
            .block(Block::default().borders(Borders::ALL).title(" Traffic Stats "))
            .wrap(Wrap { trim: true });

        frame.render_widget(right_para, right_chunks[0]);

        // Sparkline
        let history: Vec<u64> = process.history.iter().cloned().collect();
        let sparkline = Sparkline::default()
            .block(Block::default().borders(Borders::ALL).title(" Bandwidth History (10s) "))
            .data(&history)
            .style(Style::default().fg(Color::Green));
        
        frame.render_widget(sparkline, right_chunks[1]);
    }


    fn draw_connections(
        frame: &mut Frame,
        area: Rect,
        process: &crate::collector::ProcessMetrics,
        selected_index: usize,
        is_focused: bool,
        filter: &str,
    ) {
        let title = if is_focused { " Connections [FOCUS] " } else { " Connections " };
        let border_color = if is_focused { Color::Yellow } else { Color::Gray };

        let header_cells = ["Proto", "Remote Address", "Domain", "RTT", "State", "Recv", "Sent"];
        let header = Row::new(header_cells.iter().map(|h| Cell::from(*h)))
            .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
            .height(1);

        let filtered_conns: Vec<_> = process.connections.iter().filter(|c| {
            if filter.is_empty() { return true; }
            let f = filter.to_lowercase();
            c.remote_addr.to_lowercase().contains(&f) || 
            c.remote_domain.as_ref().map(|d| d.to_lowercase().contains(&f)).unwrap_or(false) ||
            c.protocol.to_lowercase().contains(&f)
        }).collect();

        let selected_index = if filtered_conns.is_empty() { 0 } else { selected_index.min(filtered_conns.len() - 1) };

        let rows = filtered_conns
            .iter()
            .enumerate()
            .map(|(i, conn)| {
                let remote = if conn.remote_port == 0 {
                    "*:*".to_string()
                } else {
                    let mut r = format!("{}:{}", conn.remote_addr, conn.remote_port);
                    if let Some(ref c) = conn.country {
                        r = format!("{} [{}]", r, c);
                    }
                    r
                };

                let domain = conn.remote_domain.as_deref().unwrap_or("-");
                let rtt = conn.rtt_ms.map(|r| format!("{}ms", r)).unwrap_or_else(|| "-".to_string());

                let mut remote_style = Style::default();
                if conn.is_suspicious {
                    remote_style = remote_style.fg(Color::Red).add_modifier(Modifier::BOLD);
                }

                let state_color = match conn.state.as_str() {
                    "ESTABLISHED" => Color::Green,
                    "LISTEN" => Color::Cyan,
                    "TIME_WAIT" => Color::Yellow,
                    "CLOSE_WAIT" | "FIN_WAIT1" | "FIN_WAIT2" => Color::Red,
                    _ => Color::Gray,
                };

                let style = if i == selected_index {
                    Style::default().bg(Color::DarkGray).fg(Color::White)
                } else if i % 2 == 0 {
                    Style::default()
                } else {
                    Style::default().bg(Color::Rgb(30, 30, 30))
                };

                let protocol_display = if conn.remote_port == 53 || conn.local_port == 53 {
                    format!("DNS ({})", conn.protocol)
                } else {
                    widgets::get_service_name(conn.remote_port, &conn.protocol)
                };

                Row::new(vec![
                    Cell::from(protocol_display),
                    Cell::from(truncate_str(&remote, 25)).style(remote_style),
                    Cell::from(truncate_str(domain, 25)).style(Style::default().fg(Color::Cyan)),
                    Cell::from(rtt).style(Style::default().fg(Color::Magenta)),
                    Cell::from(conn.state.clone()).style(Style::default().fg(state_color)),
                    Cell::from(widgets::format_bytes(conn.bytes_recv)),
                    Cell::from(widgets::format_bytes(conn.bytes_sent)),
                ])
                .style(style)
                .height(1)
            });

        let widths = vec![
            Constraint::Length(6),
            Constraint::Length(25),
            Constraint::Length(25),
            Constraint::Length(6),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(10),
        ];

        let table = Table::new(rows, widths)
            .header(header)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(border_color))
                    .title(format!(
                        "{} ({}) ",
                        title,
                        process.connections.len()
                    )),
            )
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

        let mut state = ratatui::widgets::TableState::default();
        if is_focused {
            state.select(Some(selected_index));
        }

        frame.render_stateful_widget(table, area, &mut state);
    }

    fn draw_status_bar(frame: &mut Frame, area: Rect, app: &App) {
        let filter_display = if app.detail_filter_active {
            format!("Filter: {}█", app.detail_filter_input)
        } else if !app.detail_filter_input.is_empty() {
            format!("Filter: {}", app.detail_filter_input)
        } else {
            String::new()
        };

        let help_text = if app.detail_filter_active {
            "Enter: Apply | Esc: Cancel"
        } else {
            "Esc: Back | Tab: Switch Focus | /: Search | a: Autoscroll | j/k: Scroll | w: Whois | ?: Help"
        };

        let status_spans = vec![
            Span::styled(
                if !filter_display.is_empty() {
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
