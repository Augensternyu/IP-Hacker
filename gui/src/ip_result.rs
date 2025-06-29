use log::{debug, info, warn};
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::thread;

#[derive(Debug)]
pub struct IpResult {
    pub id: u32,
    pub provider: String,
    pub ip: IpAddr,
    pub success: bool,
    pub error: String,
    pub asn: String,
    pub isp: String,
    pub country: String,
    pub region: String,
    pub city: String,
    pub time_zone: String,
    pub lat: String,
    pub lon: String,
    pub risk_score: String,
    pub tags: String,
}

impl IpResult {
    fn from_line(line: &str, id: u32) -> Option<Self> {
        let mut parts = line.split('|');
        let get_part =
            |p: &mut std::str::Split<'_, char>| -> String { p.next().unwrap_or("").to_string() };

        let provider = get_part(&mut parts);

        let ip_str = get_part(&mut parts);
        let ip = IpAddr::from_str(&ip_str).unwrap_or_else(|_| "0.0.0.0".parse().unwrap());

        let success_str = get_part(&mut parts);
        let success = success_str.parse::<bool>().unwrap_or(false);

        let error = get_part(&mut parts);
        let asn = get_part(&mut parts);
        let isp = get_part(&mut parts);
        let country = get_part(&mut parts);
        let region = get_part(&mut parts);
        let city = get_part(&mut parts);
        let time_zone = get_part(&mut parts);
        let lat = get_part(&mut parts);
        let lon = get_part(&mut parts);
        let risk_score = get_part(&mut parts);
        let tags = get_part(&mut parts);

        Some(Self {
            id,
            provider,
            ip,
            success,
            error,
            asn,
            isp,
            country,
            region,
            city,
            time_zone,
            lat,
            lon,
            risk_score,
            tags,
        })
    }
}

pub fn get_result_stream(
    command_path: &PathBuf,
    set_ip: &str,
) -> Result<Receiver<IpResult>, String> {
    let command_args = if set_ip.is_empty() {
        vec!["--special-for-gui"]
    } else {
        vec!["--special-for-gui", "--set-ip", set_ip]
    };
    let (tx, rx) = mpsc::channel();

    info!(
        "🚀 正在准备启动命令: {} {}",
        command_path.to_str().unwrap(),
        command_args.join(" ")
    );

    let mut child = Command::new(command_path)
        .args(&command_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("无法启动命令 '{}': {}", command_path.to_str().unwrap(), e))?;

    let stdout = child.stdout.take().ok_or("无法获取子进程的标准输出")?;
    let stderr = child.stderr.take().ok_or("无法获取子进程的标准错误")?;

    let _producer_thread = thread::spawn(move || {
        let reader = BufReader::new(stdout);
        let mut current_id = 0;

        for line_result in reader.lines() {
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    warn!("读取子进程输出时发生IO错误: {}", e);
                    break;
                }
            };

            if let Some(result) = IpResult::from_line(&line, current_id + 1) {
                current_id += 1;
                debug!("✅ 解析成功 (ID: {}): {:?}", result.id, result.provider);
                if tx.send(result).is_err() {
                    info!("接收端已关闭");
                    break;
                }
            }
        }

        match child.wait() {
            Ok(status) => info!("后台线程：子进程已结束，退出状态: {}", status),
            Err(e) => warn!("后台线程：等待子进程结束时出错: {}", e),
        }
    });
    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            warn!("子进程 STDERR: {}", line.unwrap_or_default());
        }
    });

    Ok(rx)
}
