
// src/utils/term.rs

// 引入 crossterm 库的相关模块
use crossterm::terminal::ClearType;
use crossterm::{cursor, execute, terminal};
// 引入标准库的 io 模块
use std::io::{stdout, Write};

// 清除屏幕
pub fn clear_screen() {
    // 执行清除所有内容并将光标移动到 (0, 0) 的操作
    execute!(
        stdout(),
        terminal::Clear(ClearType::All),
        cursor::MoveTo(0, 0)
    )
    .unwrap();
}

// 清除最后一行
pub fn clear_last_line() {
    // 使用 ANSI 转义序列清除最后一行
    // \x1B[1A: 将光标向上移动一行
    // \x1B[2K: 清除整行
    // \r: 将光标移动到行首
    print!("\x1B[1A\x1B[2K\r");
    // 刷新标准输出
    stdout().flush().unwrap();
}
