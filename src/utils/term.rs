use crossterm::terminal::ClearType;
use crossterm::{cursor, execute, terminal};
use std::io;
use std::io::{Write, stdout};

pub fn clear_screen() {
    execute!(
        stdout(),
        terminal::Clear(ClearType::All),
        cursor::MoveTo(0, 0)
    )
    .unwrap();
}

pub fn clear_last_line() {
    print!("\x1B[1A\x1B[2K\r");
    io::stdout().flush().unwrap();
}
