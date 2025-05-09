// #![warn(clippy::all, clippy::pedantic)]

use std::fmt::Write;
mod config;
mod ip_check;
mod utils;

use crate::config::default_config;
use crate::ip_check::table::gen_table;
use crate::utils::report::GLOBAL_STRING;
use crate::utils::report::{get_usage_count, post_to_pastebin};
use clap::Parser;
use log::{LevelFilter, error, info, warn};

#[tokio::main]
async fn main() {
    let args = default_config(config::Config::parse());
    log::set_logger(&utils::logger::CONSOLE_LOGGER).unwrap();

    if !args.no_logger {
        log::set_max_level(LevelFilter::Info);
    } else {
        log::set_max_level(LevelFilter::Error);
    }

    if !args.no_cls {
        utils::term::clear_screen();
    }

    if !args.no_logo {
        print_ascii_art();
    }

    if !args.no_upload {
        if let Ok((today, all)) = get_usage_count().await {
            println!("Usage: {today} / {all}");
            global_println!("Usage: {} / {}", today, all);
        } else {
            warn!("Unable to get usage count");
            global_println!("🟨 WARN: Unable to get usage count");
        }
    }

    let ip = args.set_ip.as_ref().map(|ip| {
        ip.parse::<std::net::IpAddr>().unwrap_or_else(|_| {
            error!("Invalid IP address");
            std::process::exit(1)
        })
    });

    let ip_result = ip_check::check_all(&args, ip).await;

    if args.json {
        let json_output = serde_json::to_string_pretty(&ip_result).unwrap();
        println!("{json_output}");
    } else {
        let table = gen_table(&ip_result, &args).await;
        table.printstd();
        global_println!("{}", table.to_string());
    }

    if !args.no_upload {
        match post_to_pastebin().await {
            Ok(url) => {
                info!("Result Url: {url}");
            }
            Err(err) => {
                error!("{err}");
            }
        }
    }
}

fn print_ascii_art() {
    let art = r"
   ___   ___
      / /    //   ) )         //    / /
     / /    //___/ /         //___ / /  ___      ___     / ___      ___      __
    / /    / ____ /   ____  / ___   / //   ) ) //   ) ) //\ \     //___) ) //  ) )
   / /    //               //    / / //   / / //       //  \ \   //       //
__/ /___ //               //    / / ((___( ( ((____   //    \ \ ((____   //
                                                                                   ";
    println!("{art}");
    global_println!("{}", art);
}
