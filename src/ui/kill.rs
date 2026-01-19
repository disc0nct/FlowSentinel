use super::app::App;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

pub struct KillOverlay;

impl KillOverlay {
    pub fn draw(frame: &mut Frame, app: &App) {
        if let Some(ref process) = app.selected_process {
            let area = centered_rect(40, 20, frame.area());
            frame.render_widget(Clear, area); // Clear background

            let text = vec![
                Line::from(vec![
                    Span::styled("Kill Process?", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::raw("Are you sure you want to kill:"),
                ]),
                Line::from(vec![
                    Span::styled(format!("{} (PID: {})", process.name, process.pid), Style::default().fg(Color::Yellow)),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("y/Enter: Confirm", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                    Span::raw(" | "),
                    Span::styled("n/Esc: Cancel", Style::default().fg(Color::Green)),
                ]),
            ];

            let block = Paragraph::new(text)
                .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Red)).title(" Confirm Kill "))
                .wrap(Wrap { trim: true })
                .alignment(ratatui::layout::Alignment::Center);

            frame.render_widget(block, area);
        }
    }
}

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
