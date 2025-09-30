// src/ip_check/script/hsselite_com.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, not_support_error, request_error_ip_result, Coordinates, IpResult,
    Region, AS,
}; // 引入错误处理函数和结果结构体
use crate::ip_check::script::create_reqwest_client; // 引入 reqwest 客户端创建函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use serde::Deserialize; // 引入 serde 的 Deserialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 HsseliteCom 结构体
pub struct HsseliteCom;

// 定义常量
const PROVIDER_NAME: &str = "Hsselite.com"; // 提供商名称
const API_URL: &str = "https://www.hsselite.com/ipinfo"; // API URL

// --- 用于反序列化 API JSON 响应的结构体 ---
#[derive(Deserialize, Debug)]
struct HsseliteComApiRespPayload {
    asn: Option<u32>,
    // aso: Option<String>, // 与 organization 或 isp 重复
    city: Option<String>,
    // continent_code: Option<String>,
    // country_code: Option<String>,
    country_name: Option<String>,
    ip: String,
    // is_hotspotshield_connected: bool, // 如果需要，可以作为风险标签
    isp: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    organization: Option<String>,
    region: Option<String>, // 这是区域代码，不是全名
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

// 为 HsseliteCom 实现 IpCheck trait
#[async_trait]
impl IpCheck for HsseliteCom {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            // 此 API 仅支持检查本地 IP。
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
                Ok(r) => parse_hsselite_com_resp(r).await,
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

// 解析 Hsselite.com 的 API 响应
async fn parse_hsselite_com_resp(response: Response) -> IpResult {
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

    // 将文本解析为 JSON
    let payload: HsseliteComApiRespPayload = match serde_json::from_str(&response_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = response_text.chars().take(100).collect::<String>();
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse JSON: {e}. Snippet: '{snippet}'"),
            );
        }
    };

    // 解析 IP 地址
    let Ok(parsed_ip) = payload.ip.parse::<IpAddr>() else {
        return json_parse_error_ip_result(
            PROVIDER_NAME,
            &format!("Could not parse IP from API: {}", payload.ip),
        );
    };

    // API 仅返回 IPv4 地址
    if !parsed_ip.is_ipv4() {
        return request_error_ip_result(PROVIDER_NAME, "API returned a non-IPv4 address.");
    }

    // 合并 ISP 和组织信息作为 AS 名称
    let as_name =
        sanitize_string_field(payload.isp).or(sanitize_string_field(payload.organization));

    // 构建 AS 信息
    let autonomous_system = match (payload.asn, as_name) {
        (Some(number), Some(name)) => Some(AS { number, name }),
        (None, Some(name)) => Some(AS { number: 0, name }),
        _ => None,
    };

    // 清理地理位置信息
    let country = sanitize_string_field(payload.country_name);
    let region = sanitize_string_field(payload.region);
    let city = sanitize_string_field(payload.city);

    // 解析坐标
    let coordinates = match (payload.latitude, payload.longitude) {
        (Some(lat), Some(lon)) => Some(Coordinates {
            latitude: lat.to_string(),
            longitude: lon.to_string(),
        }),
        _ => None,
    };

    // 构建 IpResult
    IpResult {
        success: true,
        error: No,
        provider: PROVIDER_NAME.to_string(),
        ip: Some(parsed_ip),
        autonomous_system,
        region: Some(Region {
            country,
            region, // 注意: 这是区域代码，如 "TPE"
            city,
            coordinates,
            time_zone: None, // API 不提供时区
        }),
        risk: None, // API 不提供明确的风险标志，除了 hotspotshield 相关的
        used_time: None,
    }
}
