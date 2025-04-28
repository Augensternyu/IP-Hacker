mod config;
mod ip_check;
mod utils;

use crate::config::default_config;
use crate::ip_check::table::gen_table;
use clap::Parser;
use log::LevelFilter;

#[tokio::main]
async fn main() -> () {
    let args = default_config(config::Config::parse());
    log::set_logger(&utils::logger::CONSOLE_LOGGER).unwrap();
    log::set_max_level(LevelFilter::Trace);

    let ip = if let Some(ip) = &args.set_ip {
        Some(ip.parse::<std::net::IpAddr>().unwrap())
    } else {
        None
    };

    let a = ip_check::check_all(&args, ip).await;
    let b = gen_table(&a, &args).await;
    b.printstd();
}
