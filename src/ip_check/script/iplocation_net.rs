// src/ip_check/script/iplocation_net.rs

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

// 定义 IplocationNet 结构体
pub struct IplocationNet;

// 定义提供商名称
const PROVIDER_NAME: &str = "Iplocation.net";
// 定义 API 基础 URL
const API_BASE_URL: &str = "https://api.iplocation.net/?ip=";

// 定义用于解析 API 响应的结构体
#[derive(Deserialize, Debug)]
struct IplocationNetApiRespPayload {
    ip: String,
    country_name: Option<String>,
    isp: Option<String>,
    response_code: String,
    response_message: String,
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

// 为 IplocationNet 实现 IpCheck trait
#[async_trait]
impl IpCheck for IplocationNet {
    // 异步检查 IP 地址
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        // API 需要一个指定的 IP 地址
        let target_ip = match ip {
            Some(ip_addr) => ip_addr,
            None => return vec![not_support_error(PROVIDER_NAME)], // 如果没有提供 IP，则返回不支持的错误
        };

        let handle = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            // API 可以通过 IPv4 或 IPv6 访问，客户端选择默认
            let client = match create_reqwest_client(None).await {
                Ok(c) => c,
                Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
            };

            let url = format!("{API_BASE_URL}{target_ip}");
            let response_result = client.get(&url).send().await;

            let mut result_without_time = match response_result {
                Ok(r) => parse_iplocation_net_resp(r).await,
                Err(e) => request_error_ip_result(PROVIDER_NAME, &e.to_string()),
            };
            result_without_time.used_time = Some(time_start.elapsed()); // 记录耗时
            result_without_time
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

// 解析 Iplocation.net 的 API 响应
async fn parse_iplocation_net_resp(response: Response) -> IpResult {
    let status = response.status();
    if !status.is_success() {
        let err_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown HTTP error".to_string());
        let err_msg = format!("HTTP Error {status}: {err_text}");
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
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

    // 解析 JSON
    let payload: IplocationNetApiRespPayload = match serde_json::from_str(&response_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = response_text.chars().take(100).collect::<String>();
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse JSON: {e}. Snippet: '{snippet}'"),
            );
        }
    };

    // 检查 API 内部的响应码
    if payload.response_code != "200" {
        return request_error_ip_result(PROVIDER_NAME, &payload.response_message);
    }

    // 解析 IP 地址
    let parsed_ip = match payload.ip.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Could not parse IP from API: {}", payload.ip),
            );
        }
    };

    // 清理和解析字段
    let country = sanitize_string_field(payload.country_name);
    let isp = sanitize_string_field(payload.isp);

    // 将 ISP 信息用作 ASN 名称
    let autonomous_system = isp.map(|name| AS { number: 0, name }); // ASN 编号未知，设为 0

    // 构建并返回 IpResult
    IpResult {
        success: true,
        error: No,
        provider: PROVIDER_NAME.to_string(),
        ip: Some(parsed_ip),
        autonomous_system,
        region: Some(Region {
            country,
            // API 不提供地区、城市、坐标或时区信息
            region: None,
            city: None,
            coordinates: None,
            time_zone: None,
        }),
        risk: None, // API 不提供风险信息
        used_time: None, // 耗时将在调用处设置
    }
}
