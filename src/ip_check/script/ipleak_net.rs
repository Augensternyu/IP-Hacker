// src/ip_check/script/ipleak_net.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, request_error_ip_result, Coordinates, IpResult, Region,
    AS,
}; // 引入IP检查结果相关的结构体和函数
use crate::ip_check::script::create_reqwest_client; // 引入创建 reqwest 客户端的函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use serde::{Deserialize, Serialize}; // 引入 serde 的 Deserialize 和 Serialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 IpleakNet 结构体
pub struct IpleakNet;

// 定义提供商名称
const PROVIDER_NAME: &str = "Ipleak.net";
// 定义 API 基础 URL
const API_BASE_URL: &str = "https://ipleak.net/?mode=json&style=dns";

// 定义用于解析 API 响应的结构体
#[derive(Deserialize, Serialize, Debug)]
struct IpleakNetApiRespPayload {
    as_number: Option<u32>,
    isp_name: Option<String>,
    // country_code: Option<String>,
    country_name: Option<String>,
    // region_code: Option<String>,
    region_name: Option<String>,
    // continent_code: Option<String>,
    // continent_name: Option<String>,
    city_name: Option<String>,
    // postal_code: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    // accuracy_radius: Option<u32>,
    time_zone: Option<String>,
    // metro_code: Option<u32>,
    ip: String, // API 为查询返回的 IP 地址
    // query_text: String, // 原始查询文本，可以是 IP 或域名
    // query_type: String, // "ip" 或 "domain"
    // 错误字段未明确定义，依赖于 HTTP 状态或缺少预期字段
}

// 清理字符串字段，移除空字符串、"-"、"未知" 或 "unknown"
fn sanitize_string_field(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim();
        // Ipleak.net 似乎对空/未知使用 null 而不是 "-"，但保持健壮性是好的
        if trimmed.is_empty()
            || trimmed == "-"
            || trimmed == "未知"
            || trimmed.to_lowercase() == "unknown"
        {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

// 为 IpleakNet 实现 IpCheck trait
#[async_trait]
impl IpCheck for IpleakNet {
    // 异步检查 IP 地址
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip_addr) = ip {
            // --- 查询指定的 IP ---
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client) = create_reqwest_client(None).await else {
                    return create_reqwest_client_error(PROVIDER_NAME);
                };

                let url = format!("{API_BASE_URL}&ip={ip_addr}");
                let response_result = client.get(&url).send().await;

                let mut result_without_time = match response_result {
                    Ok(r) => parse_ipleak_net_resp(r).await,
                    Err(e) => request_error_ip_result(PROVIDER_NAME, &e.to_string()),
                };
                result_without_time.used_time = Some(time_start.elapsed()); // 记录耗时
                result_without_time
            });

            match handle.await {
                Ok(result) => vec![result],
                Err(_) => vec![request_error_ip_result(
                    PROVIDER_NAME,
                    "Task for specific IP panicked or was cancelled.",
                )],
            }
        } else {
            // --- 查询本地 IP (尝试 IPv4 和 IPv6) ---
            let mut results = Vec::new();

            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    // 强制 IPv4
                    return create_reqwest_client_error(PROVIDER_NAME);
                };

                let response_result_v4 = client_v4.get(API_BASE_URL).send().await;
                let mut result_v4 = match response_result_v4 {
                    Ok(r) => parse_ipleak_net_resp(r).await,
                    Err(e) => {
                        request_error_ip_result(PROVIDER_NAME, &format!("IPv4 request failed: {e}"))
                    }
                };

                result_v4.used_time = Some(time_start.elapsed());
                result_v4
            });

            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                    // 强制 IPv6
                    return create_reqwest_client_error(PROVIDER_NAME);
                };

                let response_result_v6 = client_v6.get(API_BASE_URL).send().await;
                let mut result_v6 = match response_result_v6 {
                    Ok(r) => parse_ipleak_net_resp(r).await,
                    Err(e) => {
                        request_error_ip_result(PROVIDER_NAME, &format!("IPv6 request failed: {e}"))
                    }
                };
                result_v6.used_time = Some(time_start.elapsed());
                result_v6
            });

            if let Ok(r_v4) = handle_v4.await {
                results.push(r_v4);
            }
            if let Ok(r_v6) = handle_v6.await {
                let mut add_v6 = true;
                if let Some(existing_res_v4) = results.first() {
                    // 如果 IPv4 和 IPv6 的结果 IP 相同，则不重复添加
                    if existing_res_v4.success && r_v6.success && existing_res_v4.ip == r_v6.ip {
                        add_v6 = false;
                    }
                }
                if add_v6 {
                    results.push(r_v6);
                }
            }
            results
        }
    }
}

// 解析 Ipleak.net 的 API 响应
async fn parse_ipleak_net_resp(response: Response) -> IpResult {
    let status = response.status();

    if !status.is_success() {
        let err_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown HTTP error".to_string());
        let err_msg = format!(
            "HTTP Error {}: {}",
            status,
            err_text.chars().take(100).collect::<String>() // 截取前100个字符
        );
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
    }

    let response_text = match response.text().await {
        Ok(text) => text,
        Err(e) => {
            return request_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to read response text (status was {status}): {e}"),
            );
        }
    };

    // 检查是否包含 "Too many requests" 或其他纯文本错误
    if response_text.to_lowercase().contains("too many requests") {
        return request_error_ip_result(PROVIDER_NAME, "API rate limit: Too many requests.");
    }
    // API 可能会在某些错误情况下返回空响应或非 JSON 响应
    if response_text.trim().is_empty() || !response_text.trim_start().starts_with('{') {
        return json_parse_error_ip_result(
            PROVIDER_NAME,
            &format!(
                "Response was not valid JSON. Snippet: '{}'",
                response_text.chars().take(100).collect::<String>()
            ),
        );
    }

    // 解析 JSON
    let payload: IpleakNetApiRespPayload = match serde_json::from_str(&response_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = response_text.chars().take(100).collect::<String>();
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse JSON: {e}. Response snippet: '{snippet}'"),
            );
        }
    };

    // 解析 IP 地址
    let Ok(parsed_ip) = payload.ip.parse::<IpAddr>() else {
        return json_parse_error_ip_result(
            PROVIDER_NAME,
            &format!("Failed to parse 'ip' from API: '{}'", payload.ip),
        );
    };

    // 清理和解析地理位置信息
    let country = sanitize_string_field(payload.country_name);
    let region_name = sanitize_string_field(payload.region_name);
    let city = sanitize_string_field(payload.city_name);
    let time_zone = sanitize_string_field(payload.time_zone.map(|tz| tz.replace("\\/", "/"))); // 修复转义的斜杠

    // 解析 ASN 信息
    let autonomous_system = match (payload.as_number, sanitize_string_field(payload.isp_name)) {
        (Some(number), Some(name)) => Some(AS { number, name }),
        (None, Some(name)) => Some(AS { number: 0, name }),
        (Some(number), None) => Some(AS {
            number,
            name: format!("AS{number}"), // 回退名称
        }),
        (None, None) => None,
    };

    // 解析坐标
    let coordinates = match (payload.latitude, payload.longitude) {
        (Some(lat), Some(lon)) => Some(Coordinates {
            latitude: lat.to_string(),
            longitude: lon.to_string(),
        }),
        _ => None,
    };

    // 构建并返回 IpResult
    IpResult {
        success: true,
        error: No,
        provider: PROVIDER_NAME.to_string(),
        ip: Some(parsed_ip),
        autonomous_system,
        region: Some(Region {
            country,
            province: region_name,
            city,
            coordinates,
            time_zone,
        }),
        risk: None,      // API 不提供明确的风险信息
        used_time: None, // 将由调用者设置
    }
}
