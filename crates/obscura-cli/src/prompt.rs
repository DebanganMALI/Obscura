use std::io::{self, BufRead, IsTerminal, Write};

use zeroize::Zeroizing;

use crate::banner;

pub fn master_password() -> io::Result<Zeroizing<String>> {
    if io::stdin().is_terminal() {
        from_terminal()
    } else {
        from_stdin()
    }
}

fn from_terminal() -> io::Result<Zeroizing<String>> {
    banner::paint(banner::FAINT, " master  ");
    banner::paint(banner::ACCENT, "▸ ");
    io::stderr().flush()?;
    let password = Zeroizing::new(rpassword::read_password()?);
    writeln!(io::stderr())?;
    Ok(password)
}

fn from_stdin() -> io::Result<Zeroizing<String>> {
    let mut line = Zeroizing::new(String::new());
    io::stdin().lock().read_line(&mut line)?;
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}
