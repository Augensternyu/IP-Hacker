// src/ip_check/script/ipbase_com.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::RiskTag::{Hosting, Other, Proxy, Tor}; // 引入风险标签
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, request_error_ip_result, Coordinates, IpResult, Region,
    Risk, AS,
}; // 引入IP检查结果相关的结构体和函数
use crate::ip_check::script::create_reqwest_client; // 引入创建 reqwest 客户端的函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use serde::Deserialize; // 引入 serde 的 Deserialize
use std::collections::HashSet; // 引入 HashSet
use std::net::IpAddr; // 引入 IpAddr

// 定义 IpbaseCom 结构体
pub struct IpbaseCom;

// 定义提供商名称
const PROVIDER_NAME: &str = "Ipbase.com";
// 定义 API 密钥
const API_KEY: &str = "sgiPfh4j3aXFR3l2CnjWqdKQzxpqGn9pX5b3CUsz";
// 定义 API 基础 URL
const API_BASE_URL: &str = "https://api.ipbase.com/v2/info";

// --- 用于匹配 API 嵌套 JSON 响应的 Serde 结构体 ---

// 顶层响应结构体
#[derive(Deserialize, Debug)]
struct TopLevelResp {
    data: Option<ApiData>,
    errors: Option<serde_json::Value>, // 捕获潜在的错误对象
}

// 数据部分结构体
#[derive(Deserialize, Debug)]
struct ApiData {
    ip: String,
    connection: Option<ApiConnection>,
    location: Option<ApiLocation>,
    timezone: Option<ApiTimezone>,
    security: Option<ApiSecurity>,
}

// 连接信息结构体
#[derive(Deserialize, Debug)]
struct ApiConnection {
    asn: Option<u32>,
    isp: Option<String>,
}

// 地理位置信息结构体
#[derive(Deserialize, Debug)]
struct ApiLocation {
    latitude: Option<f64>,
    longitude: Option<f64>,
    country: Option<ApiCountry>,
    region: Option<ApiRegion>,
    city: Option<ApiCity>,
}

// 国家信息结构体
#[derive(Deserialize, Debug)]
struct ApiCountry {
    name: Option<String>,
}
// 地区信息结构体
#[derive(Deserialize, Debug)]
struct ApiRegion {
    name: Option<String>,
}
// 城市信息结构体
#[derive(Deserialize, Debug)]
struct ApiCity {
    name: Option<String>,
}

// 时区信息结构体
#[derive(Deserialize, Debug)]
struct ApiTimezone {
    id: Option<String>,
}

// 安全信息结构体
#[derive(Deserialize, Debug)]
struct ApiSecurity {
    is_vpn: Option<bool>,
    is_proxy: Option<bool>,
    is_tor: Option<bool>,
    is_datacenter: Option<bool>,
    is_icloud_relay: Option<bool>,
    threat_score: Option<u16>,
}

// 清理字符串字段，移除空字符串或只包含空白的字符串
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

// 为 IpbaseCom 实现 IpCheck trait
#[async_trait]
impl IpCheck for IpbaseCom {
    // 异步检查 IP 地址
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        // 根据是否提供了 IP 地址来构建 URL
        let url = if let Some(ip_addr) = ip {
            format!("{API_BASE_URL}?apikey={API_KEY}&ip={ip_addr}")
        } else {
            format!("{API_BASE_URL}?apikey={API_KEY}")
        };

        if ip.is_some() {
            // --- 查询指定的 IP ---
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let client = match create_reqwest_client(None).await {
                    Ok(c) => c,
                    Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                };

                let response_result = client.get(&url).send().await;
                let mut result_without_time = match response_result {
                    Ok(r) => parse_ipbase_com_resp(r).await,
                    Err(e) => request_error_ip_result(PROVIDER_NAME, &e.to_string()),
                };
                result_without_time.used_time = Some(time_start.elapsed()); // 记录耗时
                result_without_time
            });
            vec![handle.await.unwrap_or_else(|_| {
                request_error_ip_result(PROVIDER_NAME, "Task panicked or was cancelled.")
            })]
        } else {
            // --- 查询本地 IP (v4 和 v6) ---
            let mut results = Vec::new();
            let url_v4 = url.clone();
            let url_v6 = url;

            // 创建查询 IPv4 的任务
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let client_v4 = match create_reqwest_client(Some(false)).await {
                    Ok(c) => c,
                    Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                };

                let response_result_v4 = client_v4.get(&url_v4).send().await;
                let mut result_v4 = match response_result_v4 {
                    Ok(r) => parse_ipbase_com_resp(r).await,
                    Err(e) => request_error_ip_result(PROVIDER_NAME, &format!("IPv4 request: {e}")),
                };
                result_v4.used_time = Some(time_start.elapsed());
                result_v4
            });

            // 创建查询 IPv6 的任务
            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let client_v6 = match create_reqwest_client(Some(true)).await {
                    Ok(c) => c,
                    Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                };
                let response_result_v6 = client_v6.get(&url_v6).send().await;
                let mut result_v6 = match response_result_v6 {
                    Ok(r) => parse_ipbase_com_resp(r).await,
                    Err(e) => request_error_ip_result(PROVIDER_NAME, &format!("IPv6 request: {e}")),
                };
                result_v6.used_time = Some(time_start.elapsed());
                result_v6
            });

            // 等待并收集结果
            if let Ok(r) = handle_v4.await {
                results.push(r);
            }
            if let Ok(r) = handle_v6.await {
                // 如果 IPv6 的结果与已有的结果 IP 不同，则添加
                if !results.iter().any(|res| res.success && res.ip == r.ip) {
                    results.push(r);
                }
            }
            results
        }
    }
}

// 解析 Ipbase.com 的 API 响应
async fn parse_ipbase_com_resp(response: Response) -> IpResult {
    let status = response.status();
    if !status.is_success() {
        let err_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown HTTP error".to_string());
        let err_msg = format!("HTTP Error {status}: {err_text}");
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
    }

    // 解析 JSON
    let payload: TopLevelResp = match response.json().await {
        Ok(p) => p,
        Err(e) => return json_parse_error_ip_result(PROVIDER_NAME, &e.to_string()),
    };

    // 检查 API 是否返回错误
    if let Some(errors) = payload.errors {
        return request_error_ip_result(PROVIDER_NAME, &format!("API returned error: {errors}"));
    }

    // 获取数据部分
    let data = match payload.data {
        Some(d) => d,
        None => {
            return json_parse_error_ip_result(PROVIDER_NAME, "API response missing 'data' field.");
        }
    };

    // 解析 IP 地址
    let parsed_ip = match data.ip.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Could not parse IP from API: {}", data.ip),
            );
        }
    };

    // 解析 ASN 信息
    let autonomous_system =
        data.connection
            .and_then(|conn| match (conn.asn, sanitize_string_field(conn.isp)) {
                (Some(number), Some(name)) => Some(AS { number, name }),
                (None, Some(name)) => Some(AS { number: 0, name }), // 如果没有 ASN 编号但有名称
                _ => None,
            });

    // 解析地理位置信息
    let (country, region, city, coordinates) = if let Some(loc) = data.location {
        (
            loc.country.and_then(|c| sanitize_string_field(c.name)),
            loc.region.and_then(|r| sanitize_string_field(r.name)),
            loc.city.and_then(|c| sanitize_string_field(c.name)),
            match (loc.latitude, loc.longitude) {
                (Some(latitude), Some(longitude)) => Some(Coordinates {
                    latitude: latitude.to_string(),
                    longitude: longitude.to_string(),
                }),
                _ => None,
            },
        )
    } else {
        (None, None, None, None)
    };

    // 解析时区信息
    let time_zone = data.timezone.and_then(|tz| sanitize_string_field(tz.id));

    // 解析风险信息
    let risk = data.security.map(|sec| {
        let mut tags_set = HashSet::new();
        if sec.is_vpn == Some(true) {
            tags_set.insert(Proxy);
        }
        if sec.is_proxy == Some(true) {
            tags_set.insert(Proxy);
        }
        if sec.is_tor == Some(true) {
            tags_set.insert(Tor);
        }
        if sec.is_datacenter == Some(true) {
            tags_set.insert(Hosting);
        }
        if sec.is_icloud_relay == Some(true) {
            tags_set.insert(Other("iCloud Relay".to_string()));
        }

        let tags_vec: Vec<_> = tags_set.into_iter().collect();
        Risk {
            risk: sec.threat_score, // `threat_score` 本身就是一个风险评分
            tags: if tags_vec.is_empty() {
                None
            } else {
                Some(tags_vec)
            },
        }
    });

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
        risk,
        used_time: None, // 耗时将在调用处设置
    }
}
