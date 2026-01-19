use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

pub struct HelpOverlay;

impl HelpOverlay {
    pub fn draw(frame: &mut Frame) {
        let area = centered_rect(60, 70, frame.area());

        // Clear the background
        frame.render_widget(Clear, area);

        let help_text = vec![
            Line::from(vec![
                Span::styled("FlowSentinel Help", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Navigation", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("  j / ↓     ", Style::default().fg(Color::Green)),
                Span::raw("Move down"),
            ]),
            Line::from(vec![
                Span::styled("  k / ↑     ", Style::default().fg(Color::Green)),
                Span::raw("Move up"),
            ]),
            Line::from(vec![
                Span::styled("  g         ", Style::default().fg(Color::Green)),
                Span::raw("Go to top"),
            ]),
            Line::from(vec![
                Span::styled("  G         ", Style::default().fg(Color::Green)),
                Span::raw("Go to bottom"),
            ]),
            Line::from(vec![
                Span::styled("  Tab       ", Style::default().fg(Color::Green)),
                Span::raw("Switch focus in detail view"),
            ]),
            Line::from(vec![
                Span::styled("  Enter     ", Style::default().fg(Color::Green)),
                Span::raw("Open process details"),
            ]),
            Line::from(vec![
                Span::styled("  x         ", Style::default().fg(Color::Red)),
                Span::raw("Kill process"),
            ]),
            Line::from(vec![
                Span::styled("  w         ", Style::default().fg(Color::Green)),
                Span::raw("WHOIS lookup (Detail View)"),
            ]),
            Line::from(vec![
                Span::styled("  Shift+R   ", Style::default().fg(Color::Red)),
                Span::raw("Toggle PCAP Recording"),
            ]),
            Line::from(vec![
                Span::styled("  Esc/q     ", Style::default().fg(Color::Green)),
                Span::raw("Back / Quit"),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Controls", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("  /         ", Style::default().fg(Color::Green)),
                Span::raw("Search / Filter"),
            ]),
            Line::from(vec![
                Span::styled("  s / S     ", Style::default().fg(Color::Green)),
                Span::raw("Cycle Sort / Toggle Direction"),
            ]),
            Line::from(vec![
                Span::styled("  r         ", Style::default().fg(Color::Green)),
                Span::raw("Pause/Resume updates"),
            ]),
            Line::from(vec![
                Span::styled("  f / c     ", Style::default().fg(Color::Green)),
                Span::raw("Follow / Compact mode"),
            ]),
            Line::from(vec![
                Span::styled("  e         ", Style::default().fg(Color::Green)),
                Span::raw("Export current view"),
            ]),
            Line::from(vec![
                Span::styled("  Mouse     ", Style::default().fg(Color::Green)),
                Span::raw("Scroll wheel support"),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Filter Syntax", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            ]),
            Line::from("  name:nginx port:443 uid:1000 proto:tcp"),
            Line::from(""),
            Line::from(vec![
                Span::styled("Deep visibility enabled for DNS, HTTP, and TLS", Style::default().fg(Color::Cyan)),
            ]),
            Line::from(vec![
                Span::styled("Press any key to close", Style::default().fg(Color::DarkGray)),
            ]),
        ];

        let help = Paragraph::new(help_text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan))
                    .title(" Help "),
            )
            .wrap(Wrap { trim: true });

        frame.render_widget(help, area);
    }
}

/// Create a centered rectangle
fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
