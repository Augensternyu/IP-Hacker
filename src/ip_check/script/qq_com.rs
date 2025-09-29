// src/ip_check/script/qq_com.rs

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

// 定义 QqCom 结构体
pub struct QqCom;

// 定义提供商名称
const PROVIDER_NAME: &str = "QQ";
// 定义 API URL
const API_URL: &str = "https://r.inews.qq.com/api/ip2city?otype=json";

// 定义用于解析 API 响应的结构体
#[derive(Deserialize, Debug)]
struct QqComApiRespPayload {
    ret: i32,
    #[serde(rename = "errMsg")]
    err_msg: Option<String>,
    ip: String,
    country: Option<String>,
    province: Option<String>,
    city: Option<String>,
    isp: Option<String>,
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

// 为 QqCom 实现 IpCheck trait
#[async_trait]
impl IpCheck for QqCom {
    // 异步检查 IP 地址
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            // 此 API 仅支持检查本机 IP。
            return vec![not_support_error(PROVIDER_NAME)];
        }

        // --- 查询本机 IP (尝试 IPv4 和 IPv6) ---
        let mut results = Vec::new();

        // --- 检查本机 IPv4 ---
        let handle_v4 = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            // 强制使用 IPv4
            let client_v4 = match create_reqwest_client(Some(false)).await {
                Ok(c) => c,
                Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
            };

            let response_result_v4 = client_v4.get(API_URL).send().await;
            let mut result_v4 = match response_result_v4 {
                Ok(r) => parse_qq_com_resp(r).await,
                Err(e) => request_error_ip_result(PROVIDER_NAME, &format!("IPv4 request: {e}")),
            };
            result_v4.used_time = Some(time_start.elapsed()); // 记录耗时
            result_v4
        });

        // --- 检查本机 IPv6 ---
        let handle_v6 = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            // 强制使用 IPv6
            let client_v6 = match create_reqwest_client(Some(true)).await {
                Ok(c) => c,
                Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
            };
            let response_result_v6 = client_v6.get(API_URL).send().await;
            let mut result_v6 = match response_result_v6 {
                Ok(r) => parse_qq_com_resp(r).await,
                Err(e) => request_error_ip_result(PROVIDER_NAME, &format!("IPv6 request: {e}")),
            };
            result_v6.used_time = Some(time_start.elapsed());
            result_v6
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

// 解析 QQ.com 的 API 响应
async fn parse_qq_com_resp(response: Response) -> IpResult {
    let status = response.status();
    if !status.is_success() {
        let err_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown HTTP error".to_string());
        let err_msg = format!("HTTP Error {status}: {err_text}");
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
    }

    // API 可能返回带有回调包装器的非 JSON 响应，例如 "callback({...})"
    // 需要处理这种情况。
    let response_text = match response.text().await {
        Ok(text) => text,
        Err(e) => {
            return request_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to read response text: {e}"),
            );
        }
    };

    // 从潜在的 "callback(...)" 包装器中提取 JSON
    let json_text = if response_text.starts_with("callback(") && response_text.ends_with(')') {
        &response_text["callback(".len()..response_text.len() - 1]
    } else {
        &response_text
    };

    let payload: QqComApiRespPayload = match serde_json::from_str(json_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = json_text.chars().take(100).collect::<String>();
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse JSON: {e}. Snippet: '{snippet}'"),
            );
        }
    };

    if payload.ret != 0 {
        let err_msg = sanitize_string_field(payload.err_msg)
            .unwrap_or_else(|| "API returned non-zero status.".to_string());
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
    }

    let parsed_ip = match payload.ip.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Could not parse IP from API: {}", payload.ip),
            );
        }
    };

    let country = sanitize_string_field(payload.country);
    let region = sanitize_string_field(payload.province);
    let city = sanitize_string_field(payload.city);
    let isp = sanitize_string_field(payload.isp);

    let autonomous_system = isp.map(|name| AS { number: 0, name });

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
            coordinates: None, // API不提供坐标信息
            time_zone: None,   // API不提供时区信息
        }),
        risk: None, // API不提供风险信息
        used_time: None, // 耗时将在调用处设置
    }
}
