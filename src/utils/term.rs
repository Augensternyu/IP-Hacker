use crossterm::terminal::ClearType;
use crossterm::{cursor, execute, terminal};
use std::io::stdout;

pub fn clear_screen() {
    execute!(
        stdout(),
        terminal::Clear(ClearType::All),
        cursor::MoveTo(0, 0)
    )
    .unwrap();
}
