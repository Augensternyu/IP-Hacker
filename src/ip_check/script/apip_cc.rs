// src/ip_check/script/apip_cc.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, request_error_ip_result, Coordinates, IpResult, Region,
    AS,
}; // 引入错误处理函数和结果结构体
use crate::ip_check::script::create_reqwest_client; // 引入 reqwest 客户端创建函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use regex::Regex; // 引入 regex 库
use reqwest::Response; // 引入 reqwest 的 Response
use serde::Deserialize; // 引入 serde 的 Deserialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 ApipCc 结构体
pub struct ApipCc;

// 定义常量
const PROVIDER_NAME: &str = "Apip.cc"; // 提供商名称
const API_BASE_URL_LOCAL: &str = "https://apip.cc/json"; // 查询本机 IP 的 URL
const API_BASE_URL_SPECIFIC: &str = "https://apip.cc/api-json/"; // 查询指定 IP 的 URL

// 用于反序列化 API JSON 响应的结构体
#[derive(Deserialize, Debug)]
#[allow(non_snake_case)] // 允许非蛇形命名法以匹配 API 的 PascalCase 字段名
struct ApipCcApiRespPayload {
    status: String,
    query: String,
    CountryName: Option<String>,
    RegionName: Option<String>,
    City: Option<String>,
    Latitude: Option<String>, // API 将这些作为字符串返回
    Longitude: Option<String>,
    TimeZone: Option<String>,
    asn: Option<String>, // 例如 "AS3462"
    org: Option<String>,
    message: Option<String>, // 用于错误情况
}

// 清理字符串字段，去除首尾空格，如果是空字符串则返回 None
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

// 从字符串中解析 ASN 号码
fn parse_asn_number(asn_str_opt: Option<String>) -> Option<u32> {
    asn_str_opt.and_then(|s| {
        let re = Regex::new(r"^(AS)?(\d+)$").unwrap();
        if let Some(caps) = re.captures(&s) {
            caps.get(2).and_then(|m| m.as_str().parse::<u32>().ok())
        } else {
            None
        }
    })
}

// 为 ApipCc 实现 IpCheck trait
#[async_trait]
impl IpCheck for ApipCc {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        // API 本身通过 IPv4 访问，但可以查询 IPv4/IPv6 数据
        let Ok(client) = create_reqwest_client(Some(false)).await else {
            // 强制使用 IPv4 访问 API
            return vec![create_reqwest_client_error(PROVIDER_NAME)];
        };

        if let Some(ip_addr) = ip {
            // --- 查询指定 IP ---
            let url = format!("{API_BASE_URL_SPECIFIC}{ip_addr}");
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();

                let response_result = client.get(&url).send().await;
                let mut result_without_time = match response_result {
                    Ok(r) => parse_apip_cc_resp(r).await,
                    Err(e) => request_error_ip_result(PROVIDER_NAME, &e.to_string()),
                };
                result_without_time.used_time = Some(time_start.elapsed());
                result_without_time
            });

            match handle.await {
                Ok(result) => vec![result],
                Err(_) => vec![request_error_ip_result(
                    PROVIDER_NAME,
                    "Task panicked or was cancelled.",
                )],
            }
        } else {
            // --- 查询本机 IP ---
            // 此 API 对本机 v4 和 v6 有不同的端点，因此我们只需要一次调用。
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();

                let response_result = client.get(API_BASE_URL_LOCAL).send().await; // 路径是 /json
                let mut result_without_time = match response_result {
                    Ok(r) => parse_apip_cc_resp(r).await,
                    Err(e) => request_error_ip_result(PROVIDER_NAME, &e.to_string()),
                };
                result_without_time.used_time = Some(time_start.elapsed());
                result_without_time
            });

            match handle.await {
                Ok(result) => vec![result],
                Err(_) => vec![request_error_ip_result(
                    PROVIDER_NAME,
                    "Task panicked or was cancelled.",
                )],
            }
        }
    }
}

// 解析 Apip.cc 的 API 响应
async fn parse_apip_cc_resp(response: Response) -> IpResult {
    let status = response.status();
    if !status.is_success() {
        let err_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown HTTP error".to_string());
        let err_msg = format!("HTTP Error {status}: {err_text}");
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
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

    let payload: ApipCcApiRespPayload = match serde_json::from_str(&response_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = response_text.chars().take(100).collect::<String>();
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse JSON: {e}. Snippet: '{snippet}'"),
            );
        }
    };

    if payload.status.to_lowercase() != "success" {
        let err_msg = payload
            .message
            .unwrap_or_else(|| format!("API status was not 'success': {}", payload.status));
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
    }

    let Ok(parsed_ip) = payload.query.parse::<IpAddr>() else {
        return json_parse_error_ip_result(
            PROVIDER_NAME,
            &format!("Could not parse IP from API: {}", payload.query),
        );
    };

    let asn_number = parse_asn_number(sanitize_string_field(payload.asn));
    let as_name = sanitize_string_field(payload.org);

    let autonomous_system = match (asn_number, as_name) {
        (Some(number), Some(name)) => Some(AS { number, name }),
        (None, Some(name)) => Some(AS { number: 0, name }),
        _ => None,
    };

    let country = sanitize_string_field(payload.CountryName);
    let region = sanitize_string_field(payload.RegionName);
    let city = sanitize_string_field(payload.City);
    let time_zone = sanitize_string_field(payload.TimeZone);

    let coordinates = match (
        sanitize_string_field(payload.Latitude),
        sanitize_string_field(payload.Longitude),
    ) {
        (Some(latitude), Some(longitude)) => Some(Coordinates { latitude, longitude }),
        _ => None,
    };

    IpResult {
        success: true,
        error: No,
        provider: PROVIDER_NAME.to_string(),
        ip: Some(parsed_ip),
        autonomous_system,
        region: Some(Region {
            country,
            region,
            city,
            coordinates,
            time_zone,
        }),
        risk: None, // API 不提供风险信息
        used_time: None,
    }
}
