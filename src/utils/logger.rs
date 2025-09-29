// src/utils/logger.rs

// 引入 log 库的相关模块
use log::{Level, Metadata, Record};

// 定义一个静态的 ConsoleLogger 实例
pub static CONSOLE_LOGGER: ConsoleLogger = ConsoleLogger;

// 定义 ConsoleLogger 结构体
pub struct ConsoleLogger;

// 为 ConsoleLogger 实现 log::Log trait
impl log::Log for ConsoleLogger {
    // 判断日志是否启用
    fn enabled(&self, metadata: &Metadata) -> bool {
        if cfg!(debug_assertions) {
            // 在 debug 模式下，启用 Trace 级别及以下的日志
            metadata.level() <= Level::Trace
        } else {
            // 在 release 模式下，启用 Info 级别及以下的日志
            metadata.level() <= Level::Info
        }
    }

    // 记录日志
    fn log(&self, record: &Record) {
        // 如果日志已启用
        if self.enabled(record.metadata()) {
            // 根据日志级别进行匹配
            match record.level() {
                // 错误级别
                Level::Error => {
                    println!("🟥 ERROR: {}", record.args());
                }
                // 警告级别
                Level::Warn => {
                    println!("🟨 WARN: {}", record.args());
                }
                // 信息级别
                Level::Info => {
                    println!("🟦 INFO: {}", record.args());
                }
                // 调试级别
                Level::Debug => {
                    println!("🟩 DEBUG: {}", record.args());
                }
                // 追踪级别
                Level::Trace => {
                    println!("🟪 TRACE: {}", record.args());
                }
            }
        }
    }

    // 刷新日志
    fn flush(&self) {}
}
