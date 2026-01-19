use super::app::App;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

pub struct WhoisOverlay;

impl WhoisOverlay {
    pub fn draw(frame: &mut Frame, app: &App) {
        let area = centered_rect(70, 70, frame.area());
        frame.render_widget(Clear, area);

        let content = if let Some(ref text) = app.whois_result {
            text.clone()
        } else {
            "Querying WHOIS...".to_string()
        };

        let block = Paragraph::new(content)
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)).title(" WHOIS Lookup "))
            .wrap(Wrap { trim: false });
        
        frame.render_widget(block, area);
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
