mod app;
mod dashboard;
mod detail;
mod help;
mod kill;
mod whois;
mod widgets;

use crate::cli::Cli;
use crate::collector::Collector;
use crate::store::Store;
use anyhow::Result;
use app::App;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::sync::Arc;
use std::time::Duration;
use parking_lot::RwLock;

pub async fn run(collector: Collector, store: Arc<RwLock<Store>>, cli: Cli) -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state
    let mut app = App::new(store.clone(), cli.clone());
    let interval = cli.interval;

    // Start collector in background
    let collector_handle = tokio::spawn({
        let mut collector = collector;
        async move {
            collector.run(interval).await;
        }
    });

    // Main loop
    let result = run_app(&mut terminal, &mut app).await;

    // Cleanup
    collector_handle.abort();
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

async fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> Result<()> {
    let tick_rate = Duration::from_millis(100);

    loop {
        // Update app state from store
        app.update().await;

        // Draw UI
        terminal.draw(|f| {
            app.draw(f);
        })?;

        // Handle input
        if event::poll(tick_rate)? {
            match event::read()? {
                Event::Key(key) => {
                    // Handle Ctrl+C
                    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                        return Ok(());
                    }

                    match app.handle_key(key) {
                        app::KeyAction::Quit => return Ok(()),
                        app::KeyAction::Continue => {}
                    }
                }
                Event::Mouse(mouse) => {
                    app.handle_mouse(mouse);
                }
                _ => {}
            }
        }
    }
}
