// src/ip_check/script/realip_cc.rs

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

// 定义 RealipCc 结构体
pub struct RealipCc;

// 定义提供商名称
const PROVIDER_NAME: &str = "Realip.cc";
// 定义本机 IP 查询的 API URL
const API_BASE_URL_LOCAL: &str = "https://realip.cc/json";
// 定义指定 IP 查询的 API 基础 URL
const API_BASE_URL_SPECIFIC: &str = "https://realip.cc/";

// 定义用于解析 API 响应的结构体
#[derive(Deserialize, Serialize, Debug)]
struct RealipCcApiRespPayload {
    ip: String,
    city: Option<String>,
    province: Option<String>, // 相当于 "regionName"
    country: Option<String>,
    // continent: Option<String>,
    isp: Option<String>, // 可以是 ASN 名称或 ISP 名称
    time_zone: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    // postal_code: Option<String>,
    // iso_code: Option<String>,
    // notice: Option<String>,
    // provider: Option<String>,
    // -- 其他 IpResult 未直接使用的字段
}

// 清理字符串字段，移除空字符串、"-"、"未知" 等无效值
fn sanitize_string_field(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim();
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

// 为 RealipCc 实现 IpCheck trait
#[async_trait]
impl IpCheck for RealipCc {
    // 异步检查 IP 地址
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip_addr) = ip {
            // --- 查询指定 IP ---
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let client = match create_reqwest_client(None).await {
                    // 默认客户端
                    Ok(c) => c,
                    Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                };
                // 对于指定 IP，URL 结构不同：realip.cc/?ip=...
                let url = format!("{API_BASE_URL_SPECIFIC}?ip={ip_addr}");

                let response_result = client
                    .get(&url)
                    .header("Accept", "application/json") // 明确请求 JSON
                    .send()
                    .await;

                let mut result_without_time = match response_result {
                    Ok(r) => parse_realip_cc_resp(r).await,
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
            // --- 查询本机 IP (尝试 IPv4 和 IPv6) ---
            let mut results = Vec::new();

            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let client_v4 = match create_reqwest_client(Some(false)).await {
                    // 强制使用 IPv4
                    Ok(c) => c,
                    Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                };

                let response_result_v4 = client_v4.get(API_BASE_URL_LOCAL).send().await; // 使用 /json 路径
                let mut result_v4 = match response_result_v4 {
                    Ok(r) => parse_realip_cc_resp(r).await,
                    Err(e) => {
                        request_error_ip_result(PROVIDER_NAME, &format!("IPv4 request failed: {e}"))
                    }
                };

                result_v4.used_time = Some(time_start.elapsed());
                result_v4
            });

            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let client_v6 = match create_reqwest_client(Some(true)).await {
                    // 强制使用 IPv6
                    Ok(c) => c,
                    Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                };

                let response_result_v6 = client_v6.get(API_BASE_URL_LOCAL).send().await; // 使用 /json 路径
                let mut result_v6 = match response_result_v6 {
                    Ok(r) => parse_realip_cc_resp(r).await,
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

// 解析 Realip.cc 的 API 响应
async fn parse_realip_cc_resp(response: Response) -> IpResult {
    let status = response.status();

    if !status.is_success() {
        // API 可能会对某些错误返回纯文本错误或非 JSON
        let err_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown HTTP error".to_string());
        let err_msg = format!(
            "HTTP Error {}: {}",
            status,
            err_text.chars().take(100).collect::<String>()
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

    // 检查 API 返回的常见纯文本错误
    if response_text.to_lowercase().contains("error")
        && !response_text.trim_start().starts_with('{')
    {
        return request_error_ip_result(
            PROVIDER_NAME,
            &format!(
                "API returned plain text error. Snippet: '{}'",
                response_text.chars().take(100).collect::<String>()
            ),
        );
    }

    let payload: RealipCcApiRespPayload = match serde_json::from_str(&response_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = response_text.chars().take(100).collect::<String>();
            // 如果响应文本包含 "notice"，即使其他字段为 null，它也可能是成功的 JSON 响应
            if response_text.contains("\"notice\":") && response_text.contains("\"ip\":") {
                // 即使由于其他字段中意外的 null 导致完整解析失败，也尝试挽救 IP
                if let Ok(partial_payload) =
                    serde_json::from_str::<serde_json::Value>(&response_text)
                {
                    if let Some(ip_val) = partial_payload.get("ip").and_then(|v| v.as_str()) {
                        if let Ok(ip_addr) = ip_val.parse::<IpAddr>() {
                            // 如果我们得到了 IP 但无法解析其余部分，则返回最小成功结果
                            return IpResult {
                                success: true,
                                error: No,
                                provider: PROVIDER_NAME.to_string(),
                                ip: Some(ip_addr),
                                // ... 其他字段为 None ...
                                autonomous_system: None,
                                region: None,
                                risk: None,
                                used_time: None,
                            };
                        }
                    }
                }
            }
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse JSON: {e}. Response snippet: '{snippet}'"),
            );
        }
    };

    let parsed_ip = match payload.ip.parse::<IpAddr>() {
        Ok(ip_addr) => ip_addr,
        Err(_) => {
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse 'ip' from API: '{}'", payload.ip),
            );
        }
    };

    let country = sanitize_string_field(payload.country);
    let province = sanitize_string_field(payload.province); // 相当于 regionName
    let city = sanitize_string_field(payload.city);
    let time_zone = sanitize_string_field(payload.time_zone);

    // 'isp' 字段有时可能只是一个 ASN (如 "CLOUDFLARENET") 或一个全名。
    // 我们将其视为 AS 名称。API 不提供单独的 ASN 号码。
    let autonomous_system = sanitize_string_field(payload.isp).map(|name| AS {
        number: 0, // 未提供 ASN 号码
        name,
    });

    let coordinates = match (payload.latitude, payload.longitude) {
        (Some(lat), Some(lon)) => Some(Coordinates {
            lat: lat.to_string(),
            lon: lon.to_string(),
        }),
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
            region: province,
            city,
            coordinates,
            time_zone,
        }),
        risk: None,      // API 不提供明确的风险信息
        used_time: None, // 将由调用者设置
    }
}
