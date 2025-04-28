use log::{Level, Metadata, Record};

pub static CONSOLE_LOGGER: ConsoleLogger = ConsoleLogger;

pub struct ConsoleLogger;

impl log::Log for ConsoleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        if cfg!(debug_assertions) {
            metadata.level() <= Level::Trace
        } else {
            metadata.level() <= Level::Info
        }
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            match record.level() {
                Level::Error => {
                    println!("🟥 ERROR: {}", record.args());
                }
                Level::Warn => {
                    println!("🟨 WARN: {}", record.args());
                }
                Level::Info => {
                    println!("🟦 INFO: {}", record.args());
                }
                Level::Debug => {
                    println!("🟩 DEBUG: {}", record.args());
                }
                Level::Trace => {
                    println!("🟪 TRACE: {}", record.args());
                }
            }
        }
    }

    fn flush(&self) {}
}
