// src/ip_check/script/geoplugin_net.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, not_support_error, request_error_ip_result, Coordinates,
    IpResult, Region,
}; // 引入错误处理函数和结果结构体
use crate::ip_check::script::create_reqwest_client; // 引入 reqwest 客户端创建函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use serde::{Deserialize, Serialize}; // 引入 serde 的 Deserialize 和 Serialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 GeopluginNet 结构体
pub struct GeopluginNet;

// 定义常量
const PROVIDER_NAME: &str = "GeoPlugin.net"; // 提供商名称
const API_URL: &str = "http://www.geoplugin.net/json.gp"; // API URL (注意: 是 HTTP, 不是 HTTPS)

// --- 用于反序列化 API JSON 响应的结构体 ---
#[derive(Deserialize, Serialize, Debug)]
struct GeopluginApiRespPayload {
    #[serde(rename = "geoplugin_request")]
    ip: String,
    #[serde(rename = "geoplugin_status")]
    status: u16,
    #[serde(rename = "geoplugin_city")]
    city: Option<String>,
    #[serde(rename = "geoplugin_regionName")]
    region_name: Option<String>,
    #[serde(rename = "geoplugin_countryName")]
    country_name: Option<String>,
    #[serde(rename = "geoplugin_latitude")]
    latitude: Option<String>, // API 将这些作为字符串返回
    #[serde(rename = "geoplugin_longitude")]
    longitude: Option<String>,
    #[serde(rename = "geoplugin_timezone")]
    timezone: Option<String>,
}

// 清理字符串字段，去除首尾空格和空值
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

// 为 GeopluginNet 实现 IpCheck trait
#[async_trait]
impl IpCheck for GeopluginNet {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            // 此 API 仅支持检查发出请求的机器的本地 IP。
            return vec![not_support_error(PROVIDER_NAME)];
        }

        // --- 查询本地 IP (API 仅支持 IPv4) ---
        let handle_v4 = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            // 创建仅使用 IPv4 的 reqwest 客户端
            let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                return create_reqwest_client_error(PROVIDER_NAME);
            };

            // 发送 GET 请求
            let response_result = client_v4.get(API_URL).send().await;
            // 解析响应
            let mut result = match response_result {
                Ok(r) => parse_geoplugin_net_resp(r).await,
                Err(e) => request_error_ip_result(PROVIDER_NAME, &e.to_string()),
            };
            // 计算耗时
            result.used_time = Some(time_start.elapsed());
            result
        });

        // 等待并返回结果
        match handle_v4.await {
            Ok(result) => vec![result],
            Err(_) => vec![request_error_ip_result(
                PROVIDER_NAME,
                "Task panicked or was cancelled.",
            )],
        }
    }
}

// 解析 GeoPlugin.net 的 API 响应
async fn parse_geoplugin_net_resp(response: Response) -> IpResult {
    let status = response.status();
    if !status.is_success() {
        let err_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown HTTP error".to_string());
        let err_msg = format!("HTTP Error {status}: {err_text}");
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
    }

    // 将响应体解析为文本
    let response_text = match response.text().await {
        Ok(text) => text,
        Err(e) => {
            return request_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to read response text: {e}"),
            );
        }
    };

    // API 将 JSON 包装在回调函数 "geoplugin_(...);" 中，我们需要剥离它。
    let json_text = if response_text.starts_with("geoplugin_(") && response_text.ends_with(");") {
        &response_text["geoplugin_(".len()..response_text.len() - 2]
    } else {
        &response_text
    };

    // 将文本解析为 JSON
    let payload: GeopluginApiRespPayload = match serde_json::from_str(json_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = json_text.chars().take(100).collect::<String>();
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse JSON: {e}. Snippet: '{snippet}'"),
            );
        }
    };

    // 检查 API 返回的状态
    if payload.status != 200 && payload.status != 206 {
        // 206 表示部分内容，但仍然是 OK 的
        return request_error_ip_result(
            PROVIDER_NAME,
            &format!("API returned non-200 status: {}", payload.status),
        );
    }

    // 解析 IP 地址
    let Ok(parsed_ip) = payload.ip.parse::<IpAddr>() else {
        return json_parse_error_ip_result(
            PROVIDER_NAME,
            &format!("Could not parse IP from API: {}", payload.ip),
        );
    };

    // API 仅支持 IPv4
    if !parsed_ip.is_ipv4() {
        return request_error_ip_result(PROVIDER_NAME, "API returned a non-IPv4 address.");
    }

    // 清理地理位置信息
    let country = sanitize_string_field(payload.country_name);
    let region = sanitize_string_field(payload.region_name);
    let city = sanitize_string_field(payload.city);
    let time_zone = sanitize_string_field(payload.timezone);

    // 解析坐标
    let coordinates = match (
        sanitize_string_field(payload.latitude),
        sanitize_string_field(payload.longitude),
    ) {
        (Some(latitude), Some(longitude)) => Some(Coordinates { latitude, longitude }),
        _ => None,
    };

    // 构建 IpResult
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
            time_zone,
        }),
        risk: None, // API 不提供风险信息
        used_time: None,
    }
}
