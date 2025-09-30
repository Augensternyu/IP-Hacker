// src/ip_check/script/taobao_com.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, not_support_error, request_error_ip_result, IpResult,
    Region, AS,
}; // 引入IP检查结果相关的结构体和函数
use crate::ip_check::script::create_reqwest_client; // 引入创建 reqwest 客户端的函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use serde::Deserialize; // 引入 serde 的 Deserialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 TaobaoCom 结构体
pub struct TaobaoCom;

// 定义提供商名称
const PROVIDER_NAME: &str = "Taobao.com";
// 根据提供的示例定义 API URL 结构
const API_URL_BASE: &str = "https://ip.taobao.com/outGetIpInfo?accessKey=alibaba-inc&ip=";

// 定义用于解析 API 数据部分的结构体
#[derive(Deserialize, Debug)]
struct ApiDataPayload {
    country: Option<String>,
    region: Option<String>, // 省份
    city: Option<String>,
    isp: Option<String>,
    ip: String,
}

// 定义用于解析顶层响应的结构体
#[derive(Deserialize, Debug)]
struct TopLevelResp {
    code: i32,
    msg: String,
    data: Option<ApiDataPayload>,
}

// 清理字符串字段，移除空字符串或 "XX" (淘宝 API 用于表示未知 ISP)
fn sanitize_string_field(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() || trimmed == "XX" {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

// 为 TaobaoCom 实现 IpCheck trait
#[async_trait]
impl IpCheck for TaobaoCom {
    // 异步检查 IP 地址
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        // 此 API 仅支持检查指定的 IP，并通过 IPv4 访问。
        let target_ip = match ip {
            Some(ip_addr) => {
                if ip_addr.is_ipv6() {
                    // 根据示例和常识，该 API 似乎仅适用于 IPv4。
                    return vec![not_support_error(PROVIDER_NAME)];
                }
                ip_addr
            }
            // 此提供商必须指定 `ip`
            None => return vec![not_support_error(PROVIDER_NAME)],
        };

        let handle = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            // 强制使用 IPv4 访问 API，因为这是一个较旧的 API
            let Ok(client) = create_reqwest_client(Some(false)).await else {
                return create_reqwest_client_error(PROVIDER_NAME);
            };

            let url = format!("{API_URL_BASE}{target_ip}");
            let response_result = client.get(&url).send().await;

            let mut result = match response_result {
                Ok(r) => parse_taobao_com_resp(r).await,
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

// 解析 Taobao.com 的 API 响应
async fn parse_taobao_com_resp(response: Response) -> IpResult {
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

    if payload.code != 0 {
        return request_error_ip_result(PROVIDER_NAME, &payload.msg);
    }

    let Some(data) = payload.data else {
        return json_parse_error_ip_result(
            PROVIDER_NAME,
            "API code was 0 but 'data' field is missing.",
        );
    };

    let Ok(parsed_ip) = data.ip.parse::<IpAddr>() else {
        return json_parse_error_ip_result(
            PROVIDER_NAME,
            &format!("Could not parse IP from API: {}", data.ip),
        );
    };

    let country = sanitize_string_field(data.country);
    let region = sanitize_string_field(data.region);
    let city = sanitize_string_field(data.city);
    let isp = sanitize_string_field(data.isp);

    let autonomous_system = isp.map(|name| AS { number: 0, name });

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
            coordinates: None, // API 不提供坐标信息
            time_zone: None,   // API 不提供时区信息
        }),
        risk: None, // API 不提供风险信息
        used_time: None, // 耗时将在调用处设置
    }
}
