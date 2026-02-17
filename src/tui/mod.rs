pub mod event;

use std::io::stdout;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use anyhow::Result;
use crossbeam_channel::Receiver;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap};

use event::CaptureEvent;

const MAX_TUI_EVENTS: usize = 100_000;
const MAX_TUI_BYTES: usize = 256 * 1024 * 1024; // 256 MB total event data

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pane {
    Table,
    Detail,
}

struct AppState {
    events: Vec<CaptureEvent>,
    events_bytes: usize,
    table_state: TableState,
    detail_scroll: u16,
    focus: Pane,
    packets_seen: Arc<AtomicU64>,
    capture_running: bool,
}

impl AppState {
    fn new(packets_seen: Arc<AtomicU64>) -> Self {
        AppState {
            events: Vec::new(),
            events_bytes: 0,
            table_state: TableState::default(),
            detail_scroll: 0,
            focus: Pane::Table,
            packets_seen,
            capture_running: true,
        }
    }

    fn selected_event(&self) -> Option<&CaptureEvent> {
        self.table_state.selected().and_then(|i| self.events.get(i))
    }

    fn select_next(&mut self) {
        if self.events.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => (i + 1).min(self.events.len() - 1),
            None => 0,
        };
        self.table_state.select(Some(i));
        self.detail_scroll = 0;
    }

    fn select_prev(&mut self) {
        if self.events.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => i.saturating_sub(1),
            None => 0,
        };
        self.table_state.select(Some(i));
        self.detail_scroll = 0;
    }

    fn select_first(&mut self) {
        if !self.events.is_empty() {
            self.table_state.select(Some(0));
            self.detail_scroll = 0;
        }
    }

    fn select_last(&mut self) {
        if !self.events.is_empty() {
            self.table_state.select(Some(self.events.len() - 1));
            self.detail_scroll = 0;
        }
    }
}

pub fn run_tui(
    rx: Receiver<CaptureEvent>,
    packets_seen: Arc<AtomicU64>,
    stop_flag: Arc<AtomicBool>,
) -> Result<()> {
    // Set up terminal
    crossterm::terminal::enable_raw_mode()?;
    crossterm::execute!(stdout(), crossterm::terminal::EnterAlternateScreen)?;

    // Panic hook to restore terminal on panic
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen);
        original_hook(info);
    }));

    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;
    let mut app = AppState::new(packets_seen);

    loop {
        // Poll for keyboard input (50ms timeout)
        if crossterm::event::poll(std::time::Duration::from_millis(50))? {
            if let crossterm::event::Event::Key(key) = crossterm::event::read()? {
                if handle_key(&mut app, key, &stop_flag) {
                    break;
                }
            }
        }

        // Drain all pending events from channel
        let auto_select = app.events.is_empty();
        loop {
            match rx.try_recv() {
                Ok(event) => {
                    if app.events.len() < MAX_TUI_EVENTS && app.events_bytes < MAX_TUI_BYTES {
                        app.events_bytes += event.detail.approx_bytes();
                        app.events.push(event);
                    }
                }
                Err(_) => break,
            }
        }

        // Auto-select first event if we just got our first events
        if auto_select && !app.events.is_empty() && app.table_state.selected().is_none() {
            app.table_state.select(Some(0));
        }

        // Check if capture thread has stopped
        if stop_flag.load(Ordering::Relaxed) {
            app.capture_running = false;
        }

        // Render
        terminal.draw(|frame| render(frame, &mut app))?;
    }

    // Cleanup
    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(stdout(), crossterm::terminal::LeaveAlternateScreen)?;

    // Restore the default panic hook now that terminal is back to normal
    let _ = std::panic::take_hook();

    Ok(())
}

fn render(frame: &mut ratatui::Frame, app: &mut AppState) {
    let area = frame.area();

    let layout = Layout::vertical([
        Constraint::Min(5),
        Constraint::Percentage(40),
        Constraint::Length(1),
    ])
    .split(area);

    // --- Packet Table ---
    let header_cells = ["#", "Proto", "Source", "Dest", "Summary"].iter().map(|h| {
        Cell::from(*h).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    });
    let header = Row::new(header_cells).height(1);

    let rows: Vec<Row> = app
        .events
        .iter()
        .map(|ev| {
            let cells = [
                Cell::from(ev.id.to_string()),
                Cell::from(ev.summary.proto.as_str()),
                Cell::from(ev.summary.src.as_str()),
                Cell::from(ev.summary.dst.as_str()),
                Cell::from(ev.summary.info.as_str()),
            ];
            Row::new(cells)
        })
        .collect();

    let table_border_style = if app.focus == Pane::Table {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Length(7),
            Constraint::Length(22),
            Constraint::Length(22),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Packets ")
            .border_style(table_border_style),
    )
    .row_highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("> ");

    frame.render_stateful_widget(table, layout[0], &mut app.table_state);

    // --- Detail Pane ---
    let detail_border_style = if app.focus == Pane::Detail {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let detail_text = match app.selected_event() {
        Some(ev) => {
            let mut lines = vec![Line::from(Span::styled(
                ev.detail.header(),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ))];
            for line in ev.detail.body_text().lines() {
                lines.push(Line::from(line.to_string()));
            }
            lines
        }
        None => vec![Line::from("No packet selected")],
    };

    let detail = Paragraph::new(detail_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Detail ")
                .border_style(detail_border_style),
        )
        .wrap(Wrap { trim: false })
        .scroll((app.detail_scroll, 0));

    frame.render_widget(detail, layout[1]);

    // --- Status Bar ---
    let matched = app.events.len();
    let seen = app.packets_seen.load(Ordering::Relaxed);
    let status_indicator = if app.capture_running { "LIVE" } else { "DONE" };

    let status = Line::from(vec![
        Span::styled(
            format!(" {} ", status_indicator),
            Style::default()
                .fg(Color::Black)
                .bg(if app.capture_running {
                    Color::Green
                } else {
                    Color::Yellow
                }),
        ),
        Span::raw(format!(
            " Matched: {} | Seen: {} | q:quit  j/k:nav  Tab:focus  Home/End:jump ",
            matched, seen
        )),
    ]);

    frame.render_widget(Paragraph::new(status), layout[2]);
}

/// Returns true if the app should quit.
fn handle_key(
    app: &mut AppState,
    key: crossterm::event::KeyEvent,
    stop_flag: &Arc<AtomicBool>,
) -> bool {
    use crossterm::event::{KeyCode, KeyModifiers};

    // Ctrl+C always quits
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        stop_flag.store(true, Ordering::Relaxed);
        return true;
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            stop_flag.store(true, Ordering::Relaxed);
            true
        }
        KeyCode::Char('j') | KeyCode::Down => {
            match app.focus {
                Pane::Table => app.select_next(),
                Pane::Detail => {
                    app.detail_scroll = app.detail_scroll.saturating_add(1);
                }
            }
            false
        }
        KeyCode::Char('k') | KeyCode::Up => {
            match app.focus {
                Pane::Table => app.select_prev(),
                Pane::Detail => {
                    app.detail_scroll = app.detail_scroll.saturating_sub(1);
                }
            }
            false
        }
        KeyCode::Tab | KeyCode::Enter => {
            app.focus = match app.focus {
                Pane::Table => Pane::Detail,
                Pane::Detail => Pane::Table,
            };
            false
        }
        KeyCode::Home => {
            match app.focus {
                Pane::Table => app.select_first(),
                Pane::Detail => app.detail_scroll = 0,
            }
            false
        }
        KeyCode::End => {
            match app.focus {
                Pane::Table => app.select_last(),
                Pane::Detail => {
                    // Jump to a large scroll value; Paragraph will clamp
                    app.detail_scroll = u16::MAX;
                }
            }
            false
        }
        _ => false,
    }
}
