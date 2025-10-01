// src/ip_check/script/maptiler_com.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, not_support_error, request_error_ip_result, Coordinates,
    IpResult, Region,
}; // 引入IP检查结果相关的结构体和函数
use crate::ip_check::script::create_reqwest_client; // 引入创建 reqwest 客户端的函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use serde::Deserialize; // 引入 serde 的 Deserialize
use std::net::{IpAddr, Ipv4Addr}; // 引入 IpAddr 和 Ipv4Addr

// 定义 MaptilerCom 结构体
pub struct MaptilerCom;

// 定义提供商名称
const PROVIDER_NAME: &str = "Maptiler.com";
// 定义 API 密钥
const API_KEY: &str = "jEQqObznLQvsLCBdYQ2W";
// 定义 API URL
const API_URL: &str = "https://api.maptiler.com/geolocation/ip.json";

// 定义用于解析 API 响应的结构体
#[derive(Deserialize, Debug)]
struct MaptilerApiRespPayload {
    country: Option<String>,
    city: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    region: Option<String>,
    timezone: Option<String>,
    message: Option<String>,
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

// 为 MaptilerCom 实现 IpCheck trait
#[async_trait]
impl IpCheck for MaptilerCom {
    // 异步检查 IP 地址
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        // API 不支持查询指定 IP
        if ip.is_some() {
            return vec![not_support_error(PROVIDER_NAME)];
        }

        let mut results = Vec::new();
        let url = format!("{API_URL}?key={API_KEY}");

        // --- 检查本机 IPv4 ---
        let handle_v4 = tokio::spawn({
            let url = url.clone();
            async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error(PROVIDER_NAME);
                };

                let response_result = client_v4.get(&url).send().await;
                let mut result = match response_result {
                    Ok(r) => parse_maptiler_com_resp(r, false).await, // is_ipv6 = false
                    Err(e) => request_error_ip_result(PROVIDER_NAME, &e.to_string()),
                };
                result.used_time = Some(time_start.elapsed()); // 记录耗时
                result
            }
        });

        // --- 检查本机 IPv6 ---
        let handle_v6 = tokio::spawn({
            let url = url.clone();
            async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error(PROVIDER_NAME);
                };

                let response_result = client_v6.get(&url).send().await;
                let mut result = match response_result {
                    Ok(r) => parse_maptiler_com_resp(r, true).await, // is_ipv6 = true
                    Err(e) => request_error_ip_result(PROVIDER_NAME, &e.to_string()),
                };
                result.used_time = Some(time_start.elapsed());
                result
            }
        });

        if let Ok(r) = handle_v4.await {
            results.push(r);
        }
        if let Ok(r) = handle_v6.await {
            // 如果 IPv4 和 IPv6 的结果 IP 相同，则不重复添加
            if !results.iter().any(|res| res.success && res.ip == r.ip) {
                results.push(r);
            }
        }
        results
    }
}

// 解析 Maptiler.com 的 API 响应
async fn parse_maptiler_com_resp(response: Response, is_ipv6_request: bool) -> IpResult {
    let status = response.status();
    let response_text = match response.text().await {
        Ok(text) => text,
        Err(e) => {
            return request_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to read response text (status was {status}): {e}"),
            );
        }
    };

    if !status.is_success() {
        return request_error_ip_result(
            PROVIDER_NAME,
            &format!("HTTP Error {status}: {response_text}"),
        );
    }

    let payload: MaptilerApiRespPayload = match serde_json::from_str(&response_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = response_text.chars().take(100).collect::<String>();
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse JSON: {e}. Snippet: '{snippet}'"),
            );
        }
    };

    if let Some(message) = payload.message {
        return request_error_ip_result(PROVIDER_NAME, &message);
    }

    // **修复逻辑**: 由于 API 不返回 IP，我们构造一个占位符。
    // 如果是 IPv6 请求，我们假设成功是针对一个 IPv6 地址（我们不知道具体地址）。
    // 如果是 IPv4 请求，我们知道 IP 是一个 IPv4 地址。
    // 为简单起见，并避免在没有真实 IP 的情况下产生歧义，我们将使用一个特定的占位符。
    let placeholder_ip = if is_ipv6_request {
        // 如果我们想显示一个特定的 IPv6 占位符，我们可以使用 ::，但这可能会引起混淆。
        // 让我们为 IPv6 成功返回 None，因为我们无法知道 IP。表格逻辑会处理 None。
        // 或者，更清楚地说，我们可以使用 `is_bogon` 地址来表示它是一个占位符。
        // 一个更好的方法是返回一个特定的错误或一个没有 IP 的结果。
        // 让我们遵循请求：设置为 0.0.0.0。对于 IPv6 请求来说，这在技术上是错误的，
        // 但它满足了显示*某些内容*并避免解析错误的要求。
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    };

    let country = sanitize_string_field(payload.country);
    let province = sanitize_string_field(payload.region);
    let city = sanitize_string_field(payload.city);
    let time_zone = sanitize_string_field(payload.timezone);

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
        ip: Some(placeholder_ip), // 使用占位符
        autonomous_system: None, // API不提供ASN信息
        region: Some(Region {
            country,
            province,
            city,
            coordinates,
            time_zone,
        }),
        risk: None, // API不提供风险信息
        used_time: None, // 耗时将在调用处设置
    }
}
