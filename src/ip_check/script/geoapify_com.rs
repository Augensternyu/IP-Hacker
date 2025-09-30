// src/ip_check/script/geoapify_com.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, request_error_ip_result, Coordinates, IpResult,
    Region,
}; // 引入错误处理函数和结果结构体
use crate::ip_check::script::create_reqwest_client; // 引入 reqwest 客户端创建函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use serde::Deserialize; // 引入 serde 的 Deserialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 GeoapifyCom 结构体
pub struct GeoapifyCom;

// 定义常量
const PROVIDER_NAME: &str = "Geoapify.com"; // 提供商名称
const API_KEY: &str = "14ab66e396a34871bc315a19447af81f"; // API 密钥
const API_BASE_URL: &str = "https://api.geoapify.com/v1/ipinfo"; // API 基础 URL

// --- 用于反序列化 API JSON 响应的结构体 ---

#[derive(Deserialize, Debug)]
struct TopLevelResp {
    ip: String,
    city: Option<ApiNameObject>,
    country: Option<ApiNameObject>,
    location: Option<ApiLocation>,
    state: Option<ApiNameObject>,
    // 添加一个字段来捕获潜在的错误消息
    #[serde(rename = "error")]
    api_error: Option<ApiError>,
}

#[derive(Deserialize, Debug)]
struct ApiNameObject {
    name: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ApiLocation {
    latitude: Option<f64>,
    longitude: Option<f64>,
}

#[derive(Deserialize, Debug)]
struct ApiError {
    message: String,
    // code: String,
}

// 清理字符串字段，去除首尾空格
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

// 为 GeoapifyCom 实现 IpCheck trait
#[async_trait]
impl IpCheck for GeoapifyCom {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        // 根据是否提供 IP 构建 URL
        let url = if let Some(ip_addr) = ip {
            format!("{API_BASE_URL}?apiKey={API_KEY}&ip={ip_addr}")
        } else {
            format!("{API_BASE_URL}?apiKey={API_KEY}")
        };

        if ip.is_some() {
            // --- 查询指定 IP ---
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client) = create_reqwest_client(None).await else {
                    return create_reqwest_client_error(PROVIDER_NAME);
                };

                let response_result = client.get(&url).send().await;
                let mut result_without_time = match response_result {
                    Ok(r) => parse_geoapify_com_resp(r).await,
                    Err(e) => request_error_ip_result(PROVIDER_NAME, &e.to_string()),
                };
                result_without_time.used_time = Some(time_start.elapsed());
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
            // --- 查询本机 IP (v4 和 v6) ---
            let mut results = Vec::new();

            let handle_v4 = tokio::spawn({
                let url = url.clone();
                async move {
                    let time_start = tokio::time::Instant::now();
                    let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                        return create_reqwest_client_error(PROVIDER_NAME);
                    };

                    let response_result_v4 = client_v4.get(&url).send().await;
                    let mut result_v4 = match response_result_v4 {
                        Ok(r) => parse_geoapify_com_resp(r).await,
                        Err(e) => {
                            request_error_ip_result(PROVIDER_NAME, &format!("IPv4 request: {e}"))
                        }
                    };
                    result_v4.used_time = Some(time_start.elapsed());
                    result_v4
                }
            });

            let handle_v6 = tokio::spawn({
                let url = url.clone();
                async move {
                    let time_start = tokio::time::Instant::now();
                    let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                        return create_reqwest_client_error(PROVIDER_NAME);
                    };
                    let response_result_v6 = client_v6.get(&url).send().await;
                    let mut result_v6 = match response_result_v6 {
                        Ok(r) => parse_geoapify_com_resp(r).await,
                        Err(e) => {
                            request_error_ip_result(PROVIDER_NAME, &format!("IPv6 request: {e}"))
                        }
                    };
                    result_v6.used_time = Some(time_start.elapsed());
                    result_v6
                }
            });

            if let Ok(r) = handle_v4.await {
                results.push(r);
            }
            if let Ok(r) = handle_v6.await
                && !results.iter().any(|res| res.success && res.ip == r.ip) {
                    results.push(r);
                }
            results
        }
    }
}

// 解析 Geoapify.com 的 API 响应
async fn parse_geoapify_com_resp(response: Response) -> IpResult {
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

    // Geoapify 即使出错也返回 200 OK，错误信息在响应体中。
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

    if let Some(error) = payload.api_error {
        return request_error_ip_result(PROVIDER_NAME, &error.message);
    }

    let Ok(parsed_ip) = payload.ip.parse::<IpAddr>() else {
        return json_parse_error_ip_result(
            PROVIDER_NAME,
            &format!("Could not parse IP from API: {}", payload.ip),
        );
    };

    let country = payload.country.and_then(|c| sanitize_string_field(c.name));
    let region = payload.state.and_then(|s| sanitize_string_field(s.name));
    let city = payload.city.and_then(|c| sanitize_string_field(c.name));

    let coordinates = payload
        .location
        .and_then(|loc| match (loc.latitude, loc.longitude) {
            (Some(latitude), Some(longitude)) => Some(Coordinates {
                latitude: latitude.to_string(),
                longitude: longitude.to_string(),
            }),
            _ => None,
        });

    IpResult {
        success: true,
        error: No,
        provider: PROVIDER_NAME.to_string(),
        ip: Some(parsed_ip),
        autonomous_system: None, // API 演示不提供 ASN/ISP
        region: Some(Region {
            country,
            region,
            city,
            coordinates,
            time_zone: None, // API 演示不提供标准时区 ID
        }),
        risk: None, // API 不提供风险信息
        used_time: None,
    }
}
