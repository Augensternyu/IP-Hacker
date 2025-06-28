#![warn(clippy::all, clippy::pedantic)]

use std::fmt::Write;
mod config;
mod ip_check;
mod utils;

use crate::config::default_config;
use crate::ip_check::ip_result::{IpResultVecExt, RiskTag};
use crate::ip_check::table::gen_table;
use crate::utils::report::GLOBAL_STRING;
use crate::utils::report::get_usage_count;
use crate::utils::term::clear_last_line;
use clap::Parser;
use log::{LevelFilter, error, info, warn};
use tokio::time;
use tokio::time::Instant;

#[tokio::main]
async fn main() {
    let args = default_config(config::Config::parse());
    log::set_logger(&utils::logger::CONSOLE_LOGGER).unwrap();

    if args.logger {
        log::set_max_level(LevelFilter::Info);
    } else {
        log::set_max_level(LevelFilter::Error);
    }

    if args.cls {
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

    let time_start = Instant::now();

    let mut rx = ip_check::check_all(&args, ip).await;
    if args.json {
        let mut results_vec = Vec::new();
        while let Some(result) = rx.recv().await {
            results_vec.push(result);
        }
        results_vec.sort_by_name();
        let json_output = serde_json::to_string(&results_vec).unwrap();
        println!("{json_output}");
    } else if args.special_for_gui {
        while let Some(ip_result) = rx.recv().await {
            println!(
                "{}|{}|{}|{}|{}|{}|{}|{}",
                ip_result.provider,
                ip_result.ip.map_or(String::new(), |ip| ip.to_string()),
                ip_result.success,
                ip_result.error,
                ip_result
                    .autonomous_system
                    .map_or("|".to_string(), |asn| format!(
                        "{}|{}",
                        asn.number, asn.name
                    )),
                {
                    match ip_result.region.clone() {
                        None => "|||".to_string(),
                        Some(region) => {
                            format!(
                                "{}|{}|{}|{}",
                                region.country.unwrap_or(String::new()),
                                region.region.unwrap_or(String::new()),
                                region.city.unwrap_or(String::new()),
                                region.time_zone.unwrap_or(String::new())
                            )
                        }
                    }
                },
                {
                    match ip_result.region.clone() {
                        None => "|".to_string(),
                        Some(region) => match region.coordinates {
                            None => "|".to_string(),
                            Some(coordinates) => format!("{}|{}", coordinates.lat, coordinates.lon),
                        },
                    }
                },
                {
                    match ip_result.risk {
                        None => "|".to_string(),
                        Some(risk) => format!(
                            "{}|{}",
                            risk.risk
                                .map_or(String::new(), |risk| risk.to_string()),
                            risk.tags
                                .unwrap_or(vec![])
                                .iter()
                                .map(|tag| match tag {
                                    RiskTag::Tor => "TOR".to_string(),
                                    RiskTag::Proxy => "PROXY".to_string(),
                                    RiskTag::Hosting => "HOSTING".to_string(),
                                    RiskTag::Relay => "RELAY".to_string(),
                                    RiskTag::Mobile => "MOBILE".to_string(),
                                    RiskTag::Other(str) => str.to_string(),
                                })
                                .collect::<Vec<String>>()
                                .join(",")
                        ),
                    }
                }
            );
        }
    } else {
        let mut results = Vec::new();
        while let Some(ip_result) = rx.recv().await {
            if args.logger {
                if ip_result.success {
                    info!("{ip_result}");
                } else {
                    warn!("{ip_result}");
                }
            }
            results.push(ip_result);
        }
        let time_end = time_start.elapsed();

        if !cfg!(debug_assertions) && args.logger {
            let len = results.len();
            for _ in 0..len {
                clear_last_line();
                time::sleep(time::Duration::from_millis(10)).await;
            }
        }

        results.sort_by_name();

        let table = gen_table(&results, &args).await;
        table.printstd();
        global_println!("{}", table.to_string());

        println!("Success! Usage time: {}ms", time_end.as_millis());
        global_println!("Success! Usage time: {}ms", time_end.as_millis());
    }

    // if !args.no_upload {
    //     match post_to_pastebin().await {
    //         Ok(url) => {
    //             println!("Result Url: {url}");
    //         }
    //         Err(err) => {
    //             warn!("{err}");
    //         }
    //     }
    // }
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
