// src/ip_check/script/mullvad_net.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::RiskTag; // 引入风险标签枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, not_support_error, request_error_ip_result, Coordinates, IpResult,
    Region, Risk, AS,
}; // 引入IP检查结果相关的结构体和函数
use crate::ip_check::script::create_reqwest_client; // 引入创建 reqwest 客户端的函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use serde::Deserialize; // 引入 serde 的 Deserialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 MullvadNet 结构体
pub struct MullvadNet;

// 定义提供商名称
const PROVIDER_NAME: &str = "Mullvad.net";
// 定义 API URL
const API_URL: &str = "https://am.i.mullvad.net/json";

// --- 用于匹配 API JSON 响应的 Serde 结构体 ---

// 黑名单信息结构体
#[derive(Deserialize, Debug)]
struct BlacklistedInfo {
    blacklisted: bool,
}

// Mullvad API 响应结构体
#[derive(Deserialize, Debug)]
struct MullvadApiRespPayload {
    ip: String,
    country: Option<String>,
    city: Option<String>,
    longitude: Option<f64>,
    latitude: Option<f64>,
    mullvad_exit_ip: Option<bool>,
    blacklisted: Option<BlacklistedInfo>,
    organization: Option<String>,
}

// 清理字符串字段，移除空字符串
fn sanitize_string_field(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

// 为 MullvadNet 实现 IpCheck trait
#[async_trait]
impl IpCheck for MullvadNet {
    // 异步检查 IP 地址
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            // 此 API 仅支持检查本机 IP。
            return vec![not_support_error(PROVIDER_NAME)];
        }

        // --- 查询本机 IP (API 仅支持 IPv4) ---
        let handle_v4 = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            // 根据提示强制使用 IPv4
            let client_v4 = match create_reqwest_client(None).await {
                Ok(c) => c,
                Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
            };

            let response_result = client_v4.get(API_URL).send().await;
            let mut result = match response_result {
                Ok(r) => parse_mullvad_net_resp(r).await,
                Err(e) => request_error_ip_result(PROVIDER_NAME, &e.to_string()),
            };
            result.used_time = Some(time_start.elapsed()); // 记录耗时
            result
        });

        match handle_v4.await {
            Ok(result) => vec![result],
            Err(_) => vec![request_error_ip_result(
                PROVIDER_NAME,
                "Task panicked or was cancelled.",
            )],
        }
    }
}

// 解析 Mullvad.net 的 API 响应
async fn parse_mullvad_net_resp(response: Response) -> IpResult {
    let status = response.status();
    if !status.is_success() {
        let err_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown HTTP error".to_string());
        return request_error_ip_result(PROVIDER_NAME, &format!("HTTP Error {status}: {err_text}"));
    }

    let response_text = match response.text().await {
        Ok(text) => text,
        Err(e) => {
            return request_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to read response text: {e}"),
            );
        }
    };

    let payload: MullvadApiRespPayload = match serde_json::from_str(&response_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = response_text.chars().take(100).collect::<String>();
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse JSON: {e}. Snippet: '{snippet}'"),
            );
        }
    };

    let parsed_ip = match payload.ip.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Could not parse IP from API: {}", payload.ip),
            );
        }
    };

    let autonomous_system = sanitize_string_field(payload.organization).map(|name| AS {
        number: 0, // API 不提供 ASN 号码
        name,
    });

    let country = sanitize_string_field(payload.country);
    let city = sanitize_string_field(payload.city);

    let coordinates = match (payload.latitude, payload.longitude) {
        (Some(lat), Some(lon)) => Some(Coordinates {
            latitude: lat.to_string(),
            longitude: lon.to_string(),
        }),
        _ => None,
    };

    let mut risk_tags = Vec::new();
    if payload.mullvad_exit_ip == Some(true) {
        risk_tags.push(RiskTag::Other("Mullvad VPN".to_string()));
    }
    if let Some(bl) = payload.blacklisted
        && bl.blacklisted {
            risk_tags.push(RiskTag::Other("Blacklisted".to_string()));
        }

    // 构建并返回 IpResult
    IpResult {
        success: true,
        error: No,
        provider: PROVIDER_NAME.to_string(),
        ip: Some(parsed_ip),
        autonomous_system,
        region: Some(Region {
            country,
            region: None, // API 不提供地区信息
            city,
            coordinates,
            time_zone: None, // API 不提供时区信息
        }),
        risk: Some(Risk {
            risk: None,
            tags: if risk_tags.is_empty() {
                None
            } else {
                Some(risk_tags)
            },
        }),
        used_time: None, // 耗时将在调用处设置
    }
}
