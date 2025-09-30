// src/ip_check/script/meituan_com.rs

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
use std::net::IpAddr; // 引入 IpAddr

// 定义 MeituanCom 结构体
pub struct MeituanCom;

// 定义提供商名称
const PROVIDER_NAME: &str = "Meituan.com";
// 定义 API 基础 URL，根据提供的示例
const API_URL_BASE: &str =
    "https://apimobile.meituan.com/locate/v2/ip/loc?client_source=yourAppKey&rgeo=true&ip=";

// --- 用于匹配 API 嵌套 JSON 响应的 Serde 结构体 ---

// 反向地理编码数据结构体
#[derive(Deserialize, Debug)]
struct RgeoData {
    country: Option<String>,
    province: Option<String>,
    city: Option<String>,
    district: Option<String>,
}

// API 数据部分结构体
#[derive(Deserialize, Debug)]
struct ApiDataPayload {
    lng: Option<f64>,
    lat: Option<f64>,
    ip: String,
    rgeo: Option<RgeoData>,
}

// 顶层响应结构体
#[derive(Deserialize, Debug)]
struct TopLevelResp {
    // API 可能没有顶层的 status/code 字段，成功时直接返回数据对象。
    // 如果只是数据对象，我们将直接反序列化为 ApiDataPayload。
    // 这里我们假设它可能有一个 'data' 键。
    data: Option<ApiDataPayload>,
    // 如果错误返回不同的结构，可以添加其他潜在的顶层字段
    // 例如：code: Option<i32>, message: Option<String>
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

// 为 MeituanCom 实现 IpCheck trait
#[async_trait]
impl IpCheck for MeituanCom {
    // 异步检查 IP 地址
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        // API 需要一个指定的 IP，并且通过 IPv4 访问。
        let target_ip = match ip {
            Some(ip_addr) => {
                if ip_addr.is_ipv6() {
                    // 不支持 IPv6
                    return vec![not_support_error(PROVIDER_NAME)];
                }
                ip_addr
            }
            // 不支持查询本机 IP
            None => return vec![not_support_error(PROVIDER_NAME)],
        };

        let handle = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            // 强制使用 IPv4
            let client = match create_reqwest_client(Some(false)).await {
                Ok(c) => c,
                Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
            };

            let url = format!("{API_URL_BASE}{target_ip}");
            let response_result = client.get(&url).send().await;

            let mut result = match response_result {
                Ok(r) => parse_meituan_com_resp(r).await,
                Err(e) => request_error_ip_result(PROVIDER_NAME, &e.to_string()),
            };
            result.used_time = Some(time_start.elapsed()); // 记录耗时
            result
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

// 解析 Meituan.com 的 API 响应
async fn parse_meituan_com_resp(response: Response) -> IpResult {
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

    // 示例显示数据嵌套在 "data" 键下。
    let payload: TopLevelResp = match serde_json::from_str(&response_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = response_text.chars().take(100).collect::<String>();
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse JSON: {e}. Snippet: '{snippet}'"),
            );
        }
    };

    let data = match payload.data {
        Some(d) => d,
        None => {
            return json_parse_error_ip_result(PROVIDER_NAME, "API response missing 'data' field.");
        }
    };

    let parsed_ip = match data.ip.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Could not parse IP from API: {}", data.ip),
            );
        }
    };

    let (country, region, city) = if let Some(rgeo) = data.rgeo {
        (
            sanitize_string_field(rgeo.country),
            sanitize_string_field(rgeo.province),
            // 优先使用 city，如果 city 为空则回退到 district
            sanitize_string_field(rgeo.city).or(sanitize_string_field(rgeo.district)),
        )
    } else {
        (None, None, None)
    };

    let coordinates = match (data.lat, data.lng) {
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
        autonomous_system: None, // API 不提供 ASN/ISP
        region: Some(Region {
            country,
            region,
            city,
            coordinates,
            time_zone: None, // API 不提供时区
        }),
        risk: None,
        used_time: None, // 耗时将在调用处设置
    }
}
