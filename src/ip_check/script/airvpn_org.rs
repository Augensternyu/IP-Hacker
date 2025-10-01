// src/ip_check/script/airvpn_org.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::RiskTag; // 引入风险标签
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, not_support_error, request_error_ip_result, Coordinates, IpResult,
    Region, Risk, AS,
}; // 引入错误处理函数和结果结构体
use crate::ip_check::script::create_reqwest_client; // 引入 reqwest 客户端创建函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use serde::Deserialize; // 引入 serde 的 Deserialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 AirvpnOrg 结构体
pub struct AirvpnOrg;

// 定义常量
const PROVIDER_NAME: &str = "Airvpn.org"; // 提供商名称
const API_URL: &str = "https://airvpn.org/api/whatismyip/"; // API URL

// --- 用于反序列化 API JSON 响应的结构体 ---

#[derive(Deserialize, Debug)]
struct GeoAdditional {
    as_number: Option<u32>,
    isp_name: Option<String>,
    country_name: Option<String>,
    region_name: Option<String>,
    city_name: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    time_zone: Option<String>,
}

#[derive(Deserialize, Debug)]
struct TopLevelResp {
    ip: String,
    airvpn: Option<bool>,
    geo_additional: Option<GeoAdditional>,
    result: String,
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

// 为 AirvpnOrg 实现 IpCheck trait
#[async_trait]
impl IpCheck for AirvpnOrg {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            // 此 API 仅支持检查本机 IP
            return vec![not_support_error(PROVIDER_NAME)];
        }

        // --- 查询本机 IP (尝试 IPv4 和 IPv6) ---
        let mut results = Vec::new();

        let handle_v4 = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                return create_reqwest_client_error(PROVIDER_NAME);
            };

            let response_result = client_v4.get(API_URL).send().await;
            let mut result = match response_result {
                Ok(r) => parse_airvpn_org_resp(r).await,
                Err(e) => request_error_ip_result(PROVIDER_NAME, &e.to_string()),
            };
            result.used_time = Some(time_start.elapsed());
            result
        });

        let handle_v6 = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                return create_reqwest_client_error(PROVIDER_NAME);
            };
            let response_result = client_v6.get(API_URL).send().await;
            let mut result = match response_result {
                Ok(r) => parse_airvpn_org_resp(r).await,
                Err(e) => request_error_ip_result(PROVIDER_NAME, &e.to_string()),
            };
            result.used_time = Some(time_start.elapsed());
            result
        });

        if let Ok(r) = handle_v4.await {
            results.push(r);
        }
        if let Ok(r) = handle_v6.await {
            // 避免重复添加相同的 IP
            if !results.iter().any(|res| res.success && res.ip == r.ip) {
                results.push(r);
            }
        }
        results
    }
}

// 解析 Airvpn.org 的 API 响应
async fn parse_airvpn_org_resp(response: Response) -> IpResult {
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

    if payload.result.to_lowercase() != "ok" {
        return request_error_ip_result(PROVIDER_NAME, "API result was not 'ok'.");
    }

    let Ok(parsed_ip) = payload.ip.parse::<IpAddr>() else {
        return json_parse_error_ip_result(
            PROVIDER_NAME,
            &format!("Could not parse IP from API: {}", payload.ip),
        );
    };

    let geo_data = payload.geo_additional;

    let (autonomous_system, country, province, city, coordinates, time_zone) =
        if let Some(geo) = geo_data {
            (
                match (geo.as_number, sanitize_string_field(geo.isp_name)) {
                    (Some(number), Some(name)) => Some(AS { number, name }),
                    (None, Some(name)) => Some(AS { number: 0, name }),
                    _ => None,
                },
                sanitize_string_field(geo.country_name),
                sanitize_string_field(geo.region_name),
                sanitize_string_field(geo.city_name),
                match (geo.latitude, geo.longitude) {
                    (Some(lat), Some(lon)) => Some(Coordinates {
                        latitude: lat.to_string(),
                        longitude: lon.to_string(),
                    }),
                    _ => None,
                },
                sanitize_string_field(geo.time_zone.map(|tz| tz.replace("\\/", "/"))),
            )
        } else {
            (None, None, None, None, None, None)
        };

    let mut risk_tags = Vec::new();
    if payload.airvpn == Some(true) {
        risk_tags.push(RiskTag::Other("AirVPN".to_string()));
    }

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
        risk: Some(Risk {
            risk: None,
            tags: if risk_tags.is_empty() {
                None
            } else {
                Some(risk_tags)
            },
        }),
        used_time: None,
    }
}
