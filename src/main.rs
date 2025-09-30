#![warn(clippy::all, clippy::pedantic)] // 这行是 Clippy 的 lint 配置，用于代码检查，默认被注释掉了

use std::fmt::Write; // 引入标准库中的 Write trait，用于字符串格式化
mod config; // 引入 config 模块
mod ip_check; // 引入 ip_check 模块
mod utils; // 引入 utils 模块

use crate::config::default_config; // 从 config 模块中引入 default_config 函数
use crate::ip_check::ip_result::{IpResultVecExt, RiskTag}; // 从 ip_check::ip_result 模块中引入 IpResultVecExt trait 和 RiskTag 枚举
use crate::ip_check::table::gen_table; // 从 ip_check::table 模块中引入 gen_table 函数
use crate::utils::report::get_usage_count; // 从 utils::report 模块中引入 get_usage_count 函数
use crate::utils::report::GLOBAL_STRING; // 从 utils::report 模块中引入全局字符串变量 GLOBAL_STRING
use crate::utils::term::clear_last_line; // 从 utils::term 模块中引入 clear_last_line 函数
use clap::Parser; // 引入 clap 库的 Parser trait，用于解析命令行参数
use log::{error, info, warn, LevelFilter}; // 引入 log 库中的宏和 LevelFilter 枚举
use tokio::time; // 引入 tokio 库中的 time 模块
use tokio::time::Instant; // 引入 tokio 库中的 Instant，用于计时

#[tokio::main] // 使用 tokio 的 main 宏，将 main 函数设置为异步运行时
async fn main() {
    // 解析命令行参数并应用默认配置
    let args = default_config(config::Config::parse());
    // 设置日志记录器
    log::set_logger(&utils::logger::CONSOLE_LOGGER).unwrap();

    // 根据命令行参数设置日志级别
    if args.logger {
        log::set_max_level(LevelFilter::Info);
    } else {
        log::set_max_level(LevelFilter::Error);
    }

    // 如果需要，清空屏幕
    if args.cls {
        utils::term::clear_screen();
    }

    // 如果需要，打印 ASCII art logo
    if !args.no_logo {
        print_ascii_art();
    }

    // 如果需要，获取并打印使用次数
    if !args.no_upload {
        if let Ok((today, all)) = get_usage_count().await {
            println!("Usage: {today} / {all}");
            global_println!("Usage: {} / {}", today, all);
        } else {
            warn!("Unable to get usage count");
            global_println!("🟨 WARN: Unable to get usage count");
        }
    }

    // 解析用户指定的 IP 地址
    let ip = args.set_ip.as_ref().map(|ip| {
        ip.parse::<std::net::IpAddr>().unwrap_or_else(|_| {
            error!("Invalid IP address");
            std::process::exit(1)
        })
    });

    // 记录开始时间
    let time_start = Instant::now();

    // 调用 ip_check 模块的 check_all 函数进行 IP 查询
    let mut rx = ip_check::check_all(&args, ip).await;
    // 如果是 json 输出模式
    if args.json {
        let mut results_vec = Vec::new();
        // 从通道接收所有结果
        while let Some(result) = rx.recv().await {
            results_vec.push(result);
        }
        // 按名称排序
        results_vec.sort_by_name();
        // 将结果序列化为 JSON 字符串并打印
        let json_output = serde_json::to_string(&results_vec).unwrap();
        println!("{json_output}");
    // 如果是为 GUI 提供的特殊模式
    } else if args.special_for_gui {
        // 遍历查询结果
        while let Some(ip_result) = rx.recv().await {
            // 打印特定格式的字符串，供 GUI 解析
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
    // 默认的表格输出模式
    } else {
        let mut results = Vec::new();
        // 从通道接收所有结果
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
        // 计算总耗时
        let time_end = time_start.elapsed();

        // 在非 debug 模式下，如果开启了 logger，则清空之前的日志行
        if !cfg!(debug_assertions) && args.logger {
            let len = results.len();
            for _ in 0..len {
                clear_last_line();
                time::sleep(time::Duration::from_millis(10)).await;
            }
        }

        // 按名称对结果进行排序
        results.sort_by_name();

        // 生成表格
        let table = gen_table(&results, &args).await;
        // 打印表格到标准输出
        table.printstd();
        // 将表格内容存入全局字符串
        global_println!("{}", table.to_string());

        // 打印成功信息和耗时
        println!("Success! Usage time: {}ms", time_end.as_millis());
        global_println!("Success! Usage time: {}ms", time_end.as_millis());
    }

    // 下面的代码块被注释掉了，是用于将结果上传到 pastebin 的功能
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

// 打印 ASCII art logo 的函数
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
