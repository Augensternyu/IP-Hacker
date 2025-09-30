// src/ip_check/script/ip233_cn.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, not_support_error, request_error_ip_result, Coordinates, IpResult,
    Region, AS,
}; // 引入错误处理函数和结果结构体
use crate::ip_check::script::create_reqwest_client; // 引入 reqwest 客户端创建函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use regex::Regex; // 引入 regex 库用于正则表达式
use reqwest::header::HeaderMap; // 引入 reqwest 的 HeaderMap
use reqwest::Response; // 引入 reqwest 的 Response
use serde::Deserialize; // 引入 serde 的 Deserialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 Ip233Cn 结构体
pub struct Ip233Cn;

// 定义常量
const PROVIDER_NAME: &str = "Ip233.cn"; // 提供商名称
const API_URL_V4: &str = "https://ip.ip233.cn/ip"; // IPv4 API URL
const API_URL_V6: &str = "https://ip6.ip233.cn/ip"; // IPv6 API URL

// 为 Ip233Cn 实现 IpCheck trait
#[async_trait]
impl IpCheck for Ip233Cn {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            // 此 API 不支持查询指定 IP
            return vec![not_support_error(PROVIDER_NAME)];
        }

        let mut results = Vec::new();

        // 异步查询 IPv4 地址
        let handle_v4 = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            // 创建仅使用 IPv4 的 reqwest 客户端
            let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                return create_reqwest_client_error(PROVIDER_NAME);
            };

            // 发送 GET 请求
            let response_result = client_v4
                .get(API_URL_V4)
                .headers(ip233_style_headers().await)
                .send()
                .await;
            // 解析响应并计算耗时
            let mut result = match response_result {
                Ok(r) => parse_ip233_style_resp(r, PROVIDER_NAME).await,
                Err(e) => request_error_ip_result(PROVIDER_NAME, &format!("IPv4 request: {e}")),
            };
            result.used_time = Some(time_start.elapsed());
            result
        });

        // 异步查询 IPv6 地址
        let handle_v6 = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            // 创建仅使用 IPv6 的 reqwest 客户端
            let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                return create_reqwest_client_error(PROVIDER_NAME);
            };

            // 发送 GET 请求
            let response_result = client_v6
                .get(API_URL_V6)
                .headers(ip233_style_headers().await)
                .send()
                .await;
            // 解析响应并计算耗时
            let mut result = match response_result {
                Ok(r) => parse_ip233_style_resp(r, PROVIDER_NAME).await,
                Err(e) => request_error_ip_result(PROVIDER_NAME, &format!("IPv6 request: {e}")),
            };
            result.used_time = Some(time_start.elapsed());
            result
        });

        // 等待并收集结果
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

// --- 用于反序列化 API JSON 响应的结构体 ---
#[derive(Deserialize, Debug)]
struct Ip233StylePayload {
    ip: String,
    city: Option<String>,
    region: Option<String>,
    country_name: Option<String>,
    loc: Option<String>, // "latitude,longitude"
    org: Option<String>, // "ASxxxx ISP Name"
    timezone: Option<String>,
}

// 清理字符串字段，去除空值
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

// 从组织字符串中解析 ASN 信息
fn parse_asn_from_org(org_string_opt: Option<String>) -> Option<AS> {
    org_string_opt.and_then(|org_str| {
        let re = Regex::new(r"^(AS)?(\d+)\s*(.*)$").unwrap();
        if let Some(caps) = re.captures(&org_str) {
            let number = caps
                .get(2)
                .and_then(|m| m.as_str().parse::<u32>().ok())
                .unwrap_or(0);
            let name = caps
                .get(3)
                .map(|m| m.as_str().trim().to_string())
                .filter(|s| !s.is_empty());
            name.map(|n| AS { number, name: n })
        } else {
            Some(AS {
                number: 0,
                name: org_str,
            }) // 整个字符串都是名称
        }
    })
}

// 解析 ip233 风格的 API 响应
pub async fn parse_ip233_style_resp(response: Response, provider_name: &str) -> IpResult {
    let status = response.status();
    if !status.is_success() {
        let err_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown HTTP error".to_string());
        return request_error_ip_result(provider_name, &format!("HTTP Error {status}: {err_text}"));
    }

    // 将响应体解析为文本
    let response_text = match response.text().await {
        Ok(text) => text,
        Err(e) => {
            return request_error_ip_result(
                provider_name,
                &format!("Failed to read response text: {e}"),
            );
        }
    };

    // 将文本解析为 JSON
    let payload: Ip233StylePayload = match serde_json::from_str(&response_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = response_text.chars().take(100).collect::<String>();
            return json_parse_error_ip_result(
                provider_name,
                &format!("Failed to parse JSON: {e}. Snippet: '{snippet}'"),
            );
        }
    };

    // 解析 IP 地址
    let Ok(parsed_ip) = payload.ip.parse::<IpAddr>() else {
        return json_parse_error_ip_result(
            provider_name,
            &format!("Could not parse IP: {}", payload.ip),
        );
    };

    // 解析 ASN、地理位置等信息
    let autonomous_system = parse_asn_from_org(sanitize_string_field(payload.org));
    let country = sanitize_string_field(payload.country_name);
    let region = sanitize_string_field(payload.region);
    let city = sanitize_string_field(payload.city);
    let time_zone = sanitize_string_field(payload.timezone);

    // 解析坐标
    let coordinates = sanitize_string_field(payload.loc).and_then(|loc_str| {
        loc_str.split_once(',').map(|(lat, lon)| Coordinates {
            latitude: lat.trim().to_string(),
            longitude: lon.trim().to_string(),
        })
    });

    // 构建 IpResult
    IpResult {
        success: true,
        error: No,
        provider: provider_name.to_string(),
        ip: Some(parsed_ip),
        autonomous_system,
        region: Some(Region {
            country,
            region,
            city,
            coordinates,
            time_zone,
        }),
        risk: None,
        used_time: None,
    }
}

// 构建 ip233 风格的请求头
pub async fn ip233_style_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "Accept",
        "application/json, text/plain, */*".parse().unwrap(),
    );
    headers.insert("Accept-Language", "zh-CN,zh;q=0.9".parse().unwrap());
    headers.insert("Connection", "keep-alive".parse().unwrap());
    headers.insert("DNT", "1".parse().unwrap());
    headers.insert("Origin", "https://ip233.cn".parse().unwrap());
    headers.insert("Referer", "https://ip233.cn/".parse().unwrap());
    headers.insert("Sec-Fetch-Dest", "empty".parse().unwrap());
    headers.insert("Sec-Fetch-Mode", "cors".parse().unwrap());
    headers.insert("Sec-Fetch-Site", "same-site".parse().unwrap());
    headers.insert("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36".parse().unwrap());
    headers.insert(
        "sec-ch-ua",
        "\"Google Chrome\";v=\"137\", \"Chromium\";v=\"137\", \"Not/A)Brand\";v=\"24\""
            .parse()
            .unwrap(),
    );
    headers.insert("sec-ch-ua-mobile", "?0".parse().unwrap());
    headers.insert("sec-ch-ua-platform", "\"Linux\"".parse().unwrap());
    headers
}
