use std::io::{self, IsTerminal, Write};
use std::path::Path;

use ratatui::crossterm::execute;
use ratatui::crossterm::style::{Color, Print, ResetColor, SetForegroundColor};

pub const BONE: Color = Color::Rgb {
    r: 0xe2,
    g: 0xe1,
    b: 0xd3,
};
pub const ACCENT: Color = Color::Rgb {
    r: 0xff,
    g: 0x0a,
    b: 0x2f,
};
pub const DIM: Color = Color::Rgb {
    r: 0x9b,
    g: 0x9a,
    b: 0x8e,
};
pub const FAINT: Color = Color::Rgb {
    r: 0x6a,
    g: 0x69,
    b: 0x61,
};
pub const OK: Color = Color::Rgb {
    r: 0x7f,
    g: 0xdd,
    b: 0x92,
};

const ART: [&str; 5] = [
    " ██████╗ ██████╗ ███████╗ ██████╗██╗   ██╗██████╗  █████╗ ",
    "██╔═══██╗██╔══██╗██╔════╝██╔════╝██║   ██║██╔══██╗██╔══██╗",
    "██║   ██║██████╔╝███████╗██║     ██║   ██║██████╔╝███████║",
    "██║   ██║██╔══██╗╚════██║██║     ██║   ██║██╔══██╗██╔══██║",
    "╚██████╔╝██████╔╝███████║╚██████╗╚██████╔╝██║  ██║██║  ██║",
];

const LAST: &str = " ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝";
const RULE: &str = "──────────────────────────────────────────────────────────";

fn wanted() -> bool {
    std::env::var_os("NO_COLOR").is_none()
}

#[must_use]
pub fn visible() -> bool {
    io::stderr().is_terminal()
}

#[must_use]
pub fn out_coloured() -> bool {
    io::stdout().is_terminal() && wanted()
}

pub fn paint(colour: Color, text: &str) {
    let mut err = io::stderr();
    if visible() && wanted() {
        let _ = execute!(err, SetForegroundColor(colour), Print(text), ResetColor);
    } else if visible() {
        let _ = err.write_all(text.as_bytes());
    }
}

pub fn out_paint(colour: Color, text: &str) {
    let mut out = io::stdout();
    if out_coloured() {
        let _ = execute!(out, SetForegroundColor(colour), Print(text), ResetColor);
    } else {
        let _ = out.write_all(text.as_bytes());
    }
}

fn line(colour: Color, text: &str) {
    paint(colour, text);
    let _ = writeln!(io::stderr());
}

pub fn show() {
    if !visible() {
        return;
    }
    let _ = writeln!(io::stderr());
    for row in ART {
        line(BONE, row);
    }
    paint(BONE, LAST);
    paint(ACCENT, " ▄");
    let _ = writeln!(io::stderr());
    let _ = writeln!(io::stderr());
    line(DIM, " Everything you keep, kept to yourself.");
    line(FAINT, RULE);
}

pub fn field(label: &str, value: &str) {
    if !visible() {
        return;
    }
    paint(FAINT, &format!(" {label:<9}"));
    line(BONE, value);
}

pub fn vault(path: &Path) {
    field("vault", &path.display().to_string());
}

pub fn opened(entries: usize) {
    if !visible() {
        return;
    }
    let count = if entries == 1 {
        String::from("1 entry")
    } else {
        format!("{entries} entries")
    };
    paint(FAINT, " opened   ");
    paint(OK, &count);
    line(FAINT, " · argon2id · xchacha20-poly1305");
    let _ = writeln!(io::stderr());
}

pub fn note(text: &str) {
    if visible() {
        line(DIM, text);
    }
}

pub fn warn(text: &str) {
    if visible() {
        line(ACCENT, text);
    }
}
