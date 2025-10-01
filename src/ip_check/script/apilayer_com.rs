// src/ip_check/script/apilayer_com.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, not_support_error, request_error_ip_result, Coordinates, IpResult,
    Region, AS,
}; // 引入错误处理函数和结果结构体
use crate::ip_check::script::create_reqwest_client; // 引入 reqwest 客户端创建函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::{header, Response}; // 引入 reqwest 的 header 和 Response
use serde::Deserialize; // 引入 serde 的 Deserialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 ApilayerCom 结构体
pub struct ApilayerCom;

// 定义常量
const PROVIDER_NAME: &str = "Apilayer.com"; // 提供商名称
const API_BASE_URL: &str = "https://api.apilayer.com/ip_to_location/"; // API 基础 URL
const API_KEY: &str = "Mk25YMojGmhBUpu422bBXR0w2UT4ihc8"; // API 密钥

// --- 用于反序列化 API JSON 响应的结构体 ---

#[derive(Deserialize, Debug)]
struct TopLevelResp {
    ip: String,
    // type: String, // "ipv4" or "ipv6"
    city: Option<String>,
    region_name: Option<String>,
    country_name: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    connection: Option<ApiConnection>,
    timezones: Option<Vec<String>>,
    message: Option<String>, // 用于错误消息
}

#[derive(Deserialize, Debug)]
struct ApiConnection {
    asn: Option<u32>,
    isp: Option<String>,
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

// 为 ApilayerCom 实现 IpCheck trait
#[async_trait]
impl IpCheck for ApilayerCom {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        let target_ip = match ip {
            Some(ip_addr) => {
                if ip_addr.is_ipv6() {
                    // 根据提示中的“支持 ipv4 数据”，我们暂时假设它不支持 v6。
                    // 如果支持，可以移除此检查。
                    return vec![not_support_error(PROVIDER_NAME)];
                }
                ip_addr
            }
            // 此提供商必须指定 `ip`
            None => return vec![not_support_error(PROVIDER_NAME)],
        };

        let handle = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            let Ok(client) = create_reqwest_client(None).await else {
                // 默认客户端，因为 API 支持 IPv4/6 访问
                return create_reqwest_client_error(PROVIDER_NAME);
            };

            let url = format!("{API_BASE_URL}{target_ip}");
            let mut headers = header::HeaderMap::new();
            headers.insert("apikey", API_KEY.parse().unwrap());

            let response_result = client.get(&url).headers(headers).send().await;

            let mut result = match response_result {
                Ok(r) => parse_apilayer_com_resp(r).await,
                Err(e) => request_error_ip_result(PROVIDER_NAME, &e.to_string()),
            };
            result.used_time = Some(time_start.elapsed());
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

// 解析 Apilayer.com 的 API 响应
async fn parse_apilayer_com_resp(response: Response) -> IpResult {
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

    if let Some(message) = payload.message {
        return request_error_ip_result(PROVIDER_NAME, &message);
    }

    let Ok(parsed_ip) = payload.ip.parse::<IpAddr>() else {
        return json_parse_error_ip_result(
            PROVIDER_NAME,
            &format!("Could not parse IP from API: {}", payload.ip),
        );
    };

    let autonomous_system =
        payload
            .connection
            .and_then(|conn| match (conn.asn, sanitize_string_field(conn.isp)) {
                (Some(number), Some(name)) => Some(AS { number, name }),
                (None, Some(name)) => Some(AS { number: 0, name }),
                _ => None,
            });

    let country = sanitize_string_field(payload.country_name);
    let province = sanitize_string_field(payload.region_name);
    let city = sanitize_string_field(payload.city);
    // 从列表中获取第一个时区（如果可用）
    let time_zone = payload.timezones.and_then(|tzs| tzs.first().cloned());

    let coordinates = match (payload.latitude, payload.longitude) {
        (Some(latitude), Some(longitude)) => Some(Coordinates {
            latitude: latitude.to_string(),
            longitude: longitude.to_string(),
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
            province,
            city,
            coordinates,
            time_zone,
        }),
        risk: None, // API 不提供明确的风险信息
        used_time: None,
    }
}
