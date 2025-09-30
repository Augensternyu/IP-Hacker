// src/ip_check/script/apiip_net.rs

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
use serde::{Deserialize, Serialize}; // 引入 serde 的 Deserialize 和 Serialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 ApiipNet 结构体
pub struct ApiipNet;

// 定义常量
const PROVIDER_NAME: &str = "Apiip.net"; // 提供商名称
const API_KEY: &str = "3cfeed82-9b17-4b57-996f-65d11429120a"; // API 密钥
const API_BASE_URL: &str = "https://apiip.net/api/check"; // API 基础 URL

// 用于反序列化 API JSON 响应的结构体
#[derive(Deserialize, Serialize, Debug)]
struct ApiipNetApiRespPayload {
    ip: String,
    #[serde(rename = "countryName")]
    country_name: Option<String>,
    #[serde(rename = "regionName")]
    region_name: Option<String>,
    city: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    // 用户的演示中没有时区、ISP 或 ASN 字段。
    // 我们添加一个 'message' 字段来捕获潜在的 JSON 格式的错误消息。
    message: Option<String>,
}

// 清理字符串字段，去除首尾空格，处理空字符串和 "null" 字符串
fn sanitize_string_field(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() || trimmed.to_lowercase() == "null" {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

// 为 ApiipNet 实现 IpCheck trait
#[async_trait]
impl IpCheck for ApiipNet {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        // 根据是否提供 IP 构建 URL
        let url = if let Some(ip_addr) = ip {
            format!("{API_BASE_URL}?accessKey={API_KEY}&ip={ip_addr}")
        } else {
            format!("{API_BASE_URL}?accessKey={API_KEY}")
        };

        if ip.is_some() {
            // --- 查询指定 IP ---
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client) = create_reqwest_client(None).await else {
                    // 默认客户端
                    return create_reqwest_client_error(PROVIDER_NAME);
                };

                let response_result = client.get(&url).send().await;

                let mut result_without_time = match response_result {
                    Ok(r) => parse_apiip_net_resp(r).await,
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
            // --- 查询本机 IP (尝试 IPv4 和 IPv6) ---
            let mut results = Vec::new();

            let handle_v4 = tokio::spawn({
                let url = url.clone();
                async move {
                    let time_start = tokio::time::Instant::now();
                    let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                        // 强制 IPv4
                        return create_reqwest_client_error(PROVIDER_NAME);
                    };

                    let response_result_v4 = client_v4.get(&url).send().await;
                    let mut result_v4 = match response_result_v4 {
                        Ok(r) => parse_apiip_net_resp(r).await,
                        Err(e) => request_error_ip_result(
                            PROVIDER_NAME,
                            &format!("IPv4 request failed: {e}"),
                        ),
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
                        // 强制 IPv6
                        return create_reqwest_client_error(PROVIDER_NAME);
                    };

                    let response_result_v6 = client_v6.get(&url).send().await;
                    let mut result_v6 = match response_result_v6 {
                        Ok(r) => parse_apiip_net_resp(r).await,
                        Err(e) => request_error_ip_result(
                            PROVIDER_NAME,
                            &format!("IPv6 request failed: {e}"),
                        ),
                    };
                    result_v6.used_time = Some(time_start.elapsed());
                    result_v6
                }
            });

            if let Ok(r_v4) = handle_v4.await {
                results.push(r_v4);
            }
            if let Ok(r_v6) = handle_v6.await {
                let mut add_v6 = true;
                if let Some(existing_res_v4) = results.first()
                    && existing_res_v4.success && r_v6.success && existing_res_v4.ip == r_v6.ip {
                        add_v6 = false;
                    }
                if add_v6 {
                    results.push(r_v6);
                }
            }
            results
        }
    }
}

// 解析 Apiip.net 的 API 响应
async fn parse_apiip_net_resp(response: Response) -> IpResult {
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
        let err_msg = format!(
            "HTTP Error {}: {}",
            status,
            response_text.chars().take(200).collect::<String>()
        );
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
    }

    let payload: ApiipNetApiRespPayload = match serde_json::from_str(&response_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = response_text.chars().take(100).collect::<String>();
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse JSON: {e}. Response snippet: '{snippet}'"),
            );
        }
    };

    // API 可能返回 200 OK，但在响应体中包含错误消息，例如私有地址。
    if let Some(message) = payload.message
        && (message.to_lowercase().contains("error") || message.contains("private ip address")) {
            return request_error_ip_result(PROVIDER_NAME, &message);
        }

    let Ok(parsed_ip) = payload.ip.parse::<IpAddr>() else {
        return json_parse_error_ip_result(
            PROVIDER_NAME,
            &format!("Failed to parse 'ip' from API: '{}'", payload.ip),
        );
    };

    let country = sanitize_string_field(payload.country_name);
    let region_name = sanitize_string_field(payload.region_name);
    let city = sanitize_string_field(payload.city);

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
        autonomous_system: None, // 演示不提供 ASN/ISP 信息
        region: Some(Region {
            country,
            region: region_name,
            city,
            coordinates,
            time_zone: None, // 演示不提供时区
        }),
        risk: None,      // 演示不提供风险信息
        used_time: None, // 将由调用者设置
    }
}
