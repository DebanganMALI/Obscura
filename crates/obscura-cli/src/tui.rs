use std::time::{Duration, Instant};

use anyhow::Result;
use obscura_vault::{Entry, Vault};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{DefaultTerminal, Frame};

use crate::ordered;

const BONE: Color = Color::Rgb(0xe2, 0xe1, 0xd3);
const ACCENT: Color = Color::Rgb(0xff, 0x0a, 0x2f);
const DIM: Color = Color::Rgb(0x9b, 0x9a, 0x8e);
const FAINT: Color = Color::Rgb(0x6a, 0x69, 0x61);
const OK: Color = Color::Rgb(0x7f, 0xdd, 0x92);
const SURFACE: Color = Color::Rgb(0x1d, 0x1d, 0x23);

const TICK: Duration = Duration::from_millis(200);
const FLASH: Duration = Duration::from_secs(3);

pub enum Outcome {
    Quit,
    Locked,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Browse,
    Filter,
    Help,
}

struct App<'v> {
    vault: &'v Vault,
    shown: Vec<&'v Entry>,
    state: ListState,
    filter: String,
    mode: Mode,
    reveal: bool,
    flash: Option<(String, Color, Instant)>,
    last_input: Instant,
    idle: Duration,
    clipboard: Option<arboard::Clipboard>,
    copied: bool,
}

impl<'v> App<'v> {
    fn new(vault: &'v Vault, idle: Duration) -> Self {
        let shown = ordered(vault, None);
        let mut state = ListState::default();
        if !shown.is_empty() {
            state.select(Some(0));
        }
        Self {
            vault,
            shown,
            state,
            filter: String::new(),
            mode: Mode::Browse,
            reveal: false,
            flash: None,
            last_input: Instant::now(),
            idle,
            clipboard: arboard::Clipboard::new().ok(),
            copied: false,
        }
    }

    fn current(&self) -> Option<&'v Entry> {
        self.state
            .selected()
            .and_then(|i| self.shown.get(i))
            .copied()
    }

    fn refilter(&mut self) {
        self.shown = ordered(self.vault, Some(self.filter.as_str()));
        if self.shown.is_empty() {
            self.state.select(None);
        } else {
            let at = self.state.selected().unwrap_or(0).min(self.shown.len() - 1);
            self.state.select(Some(at));
        }
    }

    fn step(&mut self, forward: bool) {
        if self.shown.is_empty() {
            return;
        }
        let last = self.shown.len() - 1;
        let at = match self.state.selected() {
            Some(i) if forward => {
                if i >= last {
                    0
                } else {
                    i + 1
                }
            }
            Some(i) => {
                if i == 0 {
                    last
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(at));
    }

    fn say(&mut self, text: impl Into<String>, colour: Color) {
        self.flash = Some((text.into(), colour, Instant::now()));
    }

    fn copy(&mut self, label: &str, value: String) {
        if value.is_empty() {
            self.say(format!("no {label} on this entry"), FAINT);
            return;
        }
        let Some(clipboard) = self.clipboard.as_mut() else {
            self.say("no clipboard available here", ACCENT);
            return;
        };
        match clipboard.set_text(value) {
            Ok(()) => {
                self.copied = true;
                self.say(format!("{label} copied - cleared when you quit"), OK);
            }
            Err(error) => self.say(format!("clipboard refused: {error}"), ACCENT),
        }
    }

    fn copy_password(&mut self) {
        let Some(entry) = self.current() else { return };
        let value = entry.password.expose().to_owned();
        self.copy("password", value);
    }

    fn copy_username(&mut self) {
        let Some(entry) = self.current() else { return };
        let value = entry.username.clone();
        self.copy("username", value);
    }

    fn copy_totp(&mut self) {
        let Some(entry) = self.current() else { return };
        let Some(totp) = entry.totp.as_ref() else {
            self.say("no one time code on this entry", FAINT);
            return;
        };
        match totp.current() {
            Ok((code, _)) => self.copy("code", code),
            Err(error) => self.say(format!("{error}"), ACCENT),
        }
    }

    fn wipe(&mut self) {
        if self.copied {
            if let Some(clipboard) = self.clipboard.as_mut() {
                let _ = clipboard.set_text(String::new());
            }
        }
    }

    fn remaining(&self) -> u64 {
        self.idle
            .saturating_sub(self.last_input.elapsed())
            .as_secs()
    }

    fn filter_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.mode = Mode::Browse;
                self.filter.clear();
                self.refilter();
            }
            KeyCode::Enter => self.mode = Mode::Browse,
            KeyCode::Backspace => {
                self.filter.pop();
                self.refilter();
            }
            KeyCode::Char(c) => {
                self.filter.push(c);
                self.refilter();
            }
            _ => {}
        }
    }

    fn browse_key(&mut self, key: KeyEvent) -> bool {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return true;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return true,
            KeyCode::Char('j') | KeyCode::Down => self.step(true),
            KeyCode::Char('k') | KeyCode::Up => self.step(false),
            KeyCode::Char('/') => self.mode = Mode::Filter,
            KeyCode::Char('r') => self.reveal = !self.reveal,
            KeyCode::Char('?') => self.mode = Mode::Help,
            KeyCode::Char('p') => self.copy_password(),
            KeyCode::Char('u') => self.copy_username(),
            KeyCode::Char('t') => self.copy_totp(),
            _ => {}
        }
        false
    }

    fn on_key(&mut self, key: KeyEvent) -> bool {
        self.last_input = Instant::now();
        match self.mode {
            Mode::Help => {
                self.mode = Mode::Browse;
                false
            }
            Mode::Filter => {
                self.filter_key(key);
                false
            }
            Mode::Browse => self.browse_key(key),
        }
    }
}

pub fn run(vault: &Vault, idle: Duration) -> Result<Outcome> {
    let mut terminal = ratatui::init();
    let outcome = drive(&mut terminal, vault, idle);
    ratatui::restore();
    outcome
}

fn drive(terminal: &mut DefaultTerminal, vault: &Vault, idle: Duration) -> Result<Outcome> {
    let mut app = App::new(vault, idle);

    let outcome = loop {
        terminal.draw(|frame| draw(frame, &mut app))?;

        if event::poll(TICK)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press && app.on_key(key) {
                    break Outcome::Quit;
                }
            }
        }

        if let Some((_, _, at)) = app.flash {
            if at.elapsed() >= FLASH {
                app.flash = None;
            }
        }

        if app.last_input.elapsed() >= app.idle {
            break Outcome::Locked;
        }
    };

    app.wipe();
    Ok(outcome)
}

fn draw(frame: &mut Frame, app: &mut App) {
    let [top, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    let [left, right] =
        Layout::horizontal([Constraint::Length(30), Constraint::Min(0)]).areas(body);

    top_bar(frame, top, app);
    entry_list(frame, left, app);
    detail(frame, right, app);
    foot(frame, footer, app);

    if app.mode == Mode::Help {
        help_overlay(frame, frame.area());
    }
}

fn top_bar(frame: &mut Frame, area: Rect, app: &App) {
    let count = app.shown.len();
    let label = if count == 1 {
        String::from("1 entry")
    } else {
        format!("{count} entries")
    };
    let line = Line::from(vec![
        Span::styled(
            " OBSCURA",
            Style::new().fg(BONE).add_modifier(Modifier::BOLD),
        ),
        Span::styled("█ ", Style::new().fg(ACCENT)),
        Span::styled(label, Style::new().fg(FAINT)),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn entry_list(frame: &mut Frame, area: Rect, app: &mut App) {
    let items: Vec<ListItem> = app
        .shown
        .iter()
        .map(|entry| {
            let mut spans = vec![Span::styled(entry.title.clone(), Style::new().fg(BONE))];
            if entry.favorite {
                spans.push(Span::styled(" *", Style::new().fg(ACCENT)));
            }
            if entry.totp.is_some() {
                spans.push(Span::styled(" o", Style::new().fg(FAINT)));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();

    let block = Block::default()
        .borders(Borders::RIGHT)
        .border_style(Style::new().fg(SURFACE));

    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::new()
                .fg(BONE)
                .bg(SURFACE)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(" ");

    frame.render_stateful_widget(list, area, &mut app.state);
}

fn labelled(label: &str, value: String, colour: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("  {label:<10}"), Style::new().fg(FAINT)),
        Span::styled(value, Style::new().fg(colour)),
    ])
}

fn spaced(code: &str) -> String {
    let split = code.len() / 2;
    code.char_indices()
        .map(|(i, c)| {
            if i == split {
                format!(" {c}")
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn secret_lines(entry: &Entry, reveal: bool) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    if !entry.username.is_empty() {
        lines.push(labelled("username", entry.username.clone(), BONE));
    }

    let password = if reveal {
        entry.password.expose().to_owned()
    } else {
        "·".repeat(entry.password.len().min(24))
    };
    lines.push(labelled("password", password, BONE));

    if let Some(totp) = entry.totp.as_ref() {
        match totp.current() {
            Ok((code, left)) => lines.push(Line::from(vec![
                Span::styled("  code      ", Style::new().fg(FAINT)),
                Span::styled(
                    spaced(&code),
                    Style::new().fg(BONE).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("   {left}s"), Style::new().fg(ACCENT)),
            ])),
            Err(error) => lines.push(labelled("code", format!("{error}"), ACCENT)),
        }
    }

    for url in &entry.urls {
        lines.push(labelled("url", url.clone(), DIM));
    }

    for field in &entry.custom_fields {
        let value = if field.hidden && !reveal {
            "·".repeat(field.value.len().min(24))
        } else {
            field.value.expose().to_owned()
        };
        lines.push(labelled(&field.name, value, DIM));
    }

    lines
}

fn detail(frame: &mut Frame, area: Rect, app: &App) {
    let Some(entry) = app.current() else {
        let text = if app.filter.is_empty() {
            "  Nothing in this vault yet."
        } else {
            "  Nothing matches that."
        };
        frame.render_widget(
            Paragraph::new(Line::styled(text, Style::new().fg(FAINT))),
            area,
        );
        return;
    };

    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  {}", entry.title.to_uppercase()),
            Style::new().fg(BONE).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];

    lines.extend(secret_lines(entry, app.reveal));

    let notes = entry.notes.expose();
    if !notes.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {notes}"),
            Style::new().fg(DIM),
        )));
    }

    if !entry.tags.is_empty() {
        lines.push(Line::from(""));
        lines.push(labelled("tags", entry.tags.join(", "), FAINT));
    }

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

fn foot(frame: &mut Frame, area: Rect, app: &App) {
    if app.mode == Mode::Filter {
        let line = Line::from(vec![
            Span::styled(" filter ", Style::new().fg(FAINT)),
            Span::styled("> ", Style::new().fg(ACCENT)),
            Span::styled(app.filter.clone(), Style::new().fg(BONE)),
            Span::styled("_", Style::new().fg(ACCENT)),
        ]);
        frame.render_widget(Paragraph::new(line), area);
        return;
    }

    if let Some((text, colour, _)) = app.flash.as_ref() {
        let line = Line::from(Span::styled(format!(" {text}"), Style::new().fg(*colour)));
        frame.render_widget(Paragraph::new(line), area);
        return;
    }

    let hints = Line::from(Span::styled(
        "  p password   u username   t code   r reveal   / filter   ? keys   q quit",
        Style::new().fg(FAINT),
    ));
    frame.render_widget(Paragraph::new(hints), area);

    let idle = Line::from(Span::styled(
        format!("locks in {}s ", app.remaining()),
        Style::new().fg(FAINT),
    ))
    .alignment(Alignment::Right);
    frame.render_widget(Paragraph::new(idle), area);
}

fn help_overlay(frame: &mut Frame, area: Rect) {
    let [_, middle, _] = Layout::vertical([
        Constraint::Percentage(20),
        Constraint::Length(12),
        Constraint::Min(0),
    ])
    .areas(area);
    let [_, centre, _] = Layout::horizontal([
        Constraint::Percentage(25),
        Constraint::Length(44),
        Constraint::Min(0),
    ])
    .areas(middle);

    let rows = [
        ("j / down", "next entry"),
        ("k / up", "previous entry"),
        ("/", "filter, esc clears"),
        ("p", "copy the password"),
        ("u", "copy the username"),
        ("t", "copy the one time code"),
        ("r", "reveal or hide secrets"),
        ("q / esc", "quit and wipe the clipboard"),
    ];

    let mut lines = vec![Line::from("")];
    for (key, what) in rows {
        lines.push(Line::from(vec![
            Span::styled(format!("   {key:<12}"), Style::new().fg(ACCENT)),
            Span::styled(what, Style::new().fg(BONE)),
        ]));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(FAINT))
        .title(Span::styled(" keys ", Style::new().fg(BONE)));

    frame.render_widget(Clear, centre);
    frame.render_widget(Paragraph::new(lines).block(block), centre);
}
