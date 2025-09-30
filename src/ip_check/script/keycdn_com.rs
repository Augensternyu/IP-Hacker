// src/ip_check/script/keycdn_com.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, not_support_error, request_error_ip_result, Coordinates, IpResult,
    Region, AS,
}; // 引入IP检查结果相关的结构体和函数
use crate::ip_check::script::create_reqwest_client; // 引入创建 reqwest 客户端的函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::{header, Response}; // 引入 reqwest 的 header 和 Response
use serde::Deserialize; // 引入 serde 的 Deserialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 KeycdnCom 结构体
pub struct KeycdnCom;

// 定义提供商名称
const PROVIDER_NAME: &str = "Keycdn.com";
// 定义 API 基础 URL
const API_BASE_URL: &str = "https://tools.keycdn.com/geo.json";

// --- 用于匹配 API 嵌套 JSON 响应的 Serde 结构体 ---

// 顶层响应结构体
#[derive(Deserialize, Debug)]
struct TopLevelResp {
    status: String,
    description: Option<String>,
    data: Option<ApiData>,
}

// 数据部分结构体
#[derive(Deserialize, Debug)]
struct ApiData {
    geo: ApiGeo,
}

// 地理位置信息结构体
#[derive(Deserialize, Debug)]
struct ApiGeo {
    ip: String,
    asn: Option<u32>,
    isp: Option<String>,
    country_name: Option<String>,
    region_name: Option<String>,
    city: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    timezone: Option<String>,
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

// 为 KeycdnCom 实现 IpCheck trait
#[async_trait]
impl IpCheck for KeycdnCom {
    // 异步检查 IP 地址
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        let Some(target_ip) = ip else {
            // API 需要一个指定的 IP 地址
            return vec![not_support_error(PROVIDER_NAME)];
        };

        let handle = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            let Ok(client) = create_reqwest_client(None).await else {
                return create_reqwest_client_error(PROVIDER_NAME);
            };

            let url = format!("{API_BASE_URL}?host={target_ip}");
            let mut headers = header::HeaderMap::new();
            // User-Agent 对此 API 至关重要
            headers.insert(
                header::USER_AGENT,
                "keycdn-tools:https://yoursite.com".parse().unwrap(),
            );

            let response_result = client.get(&url).headers(headers).send().await;

            let mut result = match response_result {
                Ok(r) => parse_keycdn_com_resp(r).await,
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

// 解析 Keycdn.com 的 API 响应
async fn parse_keycdn_com_resp(response: Response) -> IpResult {
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

    if payload.status != "success" {
        let err_msg = payload
            .description
            .unwrap_or_else(|| "API status was not 'success'.".to_string());
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
    }

    let geo_data = match payload.data {
        Some(data) => data.geo,
        None => {
            return json_parse_error_ip_result(PROVIDER_NAME, "API response missing 'data' field.");
        }
    };

    let Ok(parsed_ip) = geo_data.ip.parse::<IpAddr>() else {
        return json_parse_error_ip_result(
            PROVIDER_NAME,
            &format!("Could not parse IP from API: {}", geo_data.ip),
        );
    };

    let autonomous_system = match (geo_data.asn, sanitize_string_field(geo_data.isp)) {
        (Some(number), Some(name)) => Some(AS { number, name }),
        (None, Some(name)) => Some(AS { number: 0, name }),
        _ => None,
    };

    let country = sanitize_string_field(geo_data.country_name);
    let region = sanitize_string_field(geo_data.region_name);
    let city = sanitize_string_field(geo_data.city);
    let time_zone = sanitize_string_field(geo_data.timezone);

    let coordinates = match (geo_data.latitude, geo_data.longitude) {
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
            region,
            city,
            coordinates,
            time_zone,
        }),
        risk: None, // API 不提供风险信息
        used_time: None, // 耗时将在调用处设置
    }
}
