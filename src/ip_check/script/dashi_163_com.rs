// src/ip_check/script/dashi_163_com.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, not_support_error, request_error_ip_result, Coordinates, IpResult,
    Region, AS,
}; // 引入错误处理函数和结果结构体
use crate::ip_check::script::create_reqwest_client; // 引入 reqwest 客户端创建函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use serde::Deserialize; // 引入 serde 的 Deserialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 Dashi163Com 结构体
pub struct Dashi163Com;

// 定义常量
const PROVIDER_NAME: &str = "Dashi.163.com"; // 提供商名称
const API_URL: &str = "https://dashi.163.com/fgw/mailsrv-ipdetail/detail"; // API URL

// --- 用于反序列化 API JSON 响应的结构体 ---

#[derive(Deserialize, Debug)]
struct ApiResultData {
    country: Option<String>,
    province: Option<String>,
    city: Option<String>,
    isp: Option<String>,
    latitude: Option<String>,
    longitude: Option<String>,
    timezone: Option<String>,
    ip: String,
}

#[derive(Deserialize, Debug)]
struct TopLevelResp {
    code: i32,
    #[serde(rename = "success")]
    _success: String, // 此字段不可靠，忽略其值
    result: Option<ApiResultData>,
    desc: Option<String>,
}

// 清理字符串字段，去除首尾空格和无效值
fn sanitize_string_field(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() || trimmed.to_uppercase() == "UNKNOWN" {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

// 为 Dashi163Com 实现 IpCheck trait
#[async_trait]
impl IpCheck for Dashi163Com {
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
            let response_result_v4 = client_v4.get(API_URL).send().await;
            // 解析响应
            let mut result_v4 = match response_result_v4 {
                Ok(r) => parse_dashi_163_com_resp(r).await,
                Err(e) => request_error_ip_result(PROVIDER_NAME, &format!("IPv4 request: {e}")),
            };
            // 计算耗时
            result_v4.used_time = Some(time_start.elapsed());
            result_v4
        });

        // 异步查询 IPv6 地址
        let handle_v6 = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            // 创建仅使用 IPv6 的 reqwest 客户端
            let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                return create_reqwest_client_error(PROVIDER_NAME);
            };
            // 发送 GET 请求
            let response_result_v6 = client_v6.get(API_URL).send().await;
            // 解析响应
            let mut result_v6 = match response_result_v6 {
                Ok(r) => parse_dashi_163_com_resp(r).await,
                Err(e) => request_error_ip_result(PROVIDER_NAME, &format!("IPv6 request: {e}")),
            };
            // 计算耗时
            result_v6.used_time = Some(time_start.elapsed());
            result_v6
        });

        // 等待并收集结果
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

// 解析 Dashi.163.com 的 API 响应
async fn parse_dashi_163_com_resp(response: Response) -> IpResult {
    let status = response.status();
    if !status.is_success() {
        let err_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown HTTP error".to_string());
        let err_msg = format!("HTTP Error {status}: {err_text}");
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
    }

    // 将响应体解析为文本
    let response_text = match response.text().await {
        Ok(text) => text,
        Err(e) => {
            return request_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to read response text: {e}"),
            );
        }
    };

    // 将文本解析为 JSON
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

    // 检查 API 返回的状态码
    if payload.code != 200 {
        let err_msg = payload
            .desc
            .unwrap_or_else(|| "API returned non-200 code.".to_string());
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
    }

    // 获取数据部分
    let Some(ref data) = payload.result else {
        return json_parse_error_ip_result(
            PROVIDER_NAME,
            "API code was 200 but 'result' field is missing.",
        );
    };

    // 解析 IP 地址
    let Ok(parsed_ip) = data.ip.parse::<IpAddr>() else {
        return json_parse_error_ip_result(
            PROVIDER_NAME,
            &format!("Could not parse IP from API: {}", data.ip),
        );
    };

    // 清理地理位置和 ISP 信息
    let country = sanitize_string_field(data.country.clone());
    let province = sanitize_string_field(data.province.clone());
    let city = sanitize_string_field(data.city.clone());
    let isp = sanitize_string_field(data.isp.clone());
    let time_zone = sanitize_string_field(data.timezone.clone());

    let autonomous_system = isp.map(|name| AS { number: 0, name });

    // 解析坐标
    let coordinates = match (
        sanitize_string_field(payload.result.as_ref().and_then(|r| r.latitude.clone())),
        sanitize_string_field(payload.result.as_ref().and_then(|r| r.longitude.clone())),
    ) {
        (Some(latitude), Some(longitude)) => Some(Coordinates { latitude, longitude }),
        _ => None,
    };

    // 构建 IpResult
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
        risk: None,
        used_time: None,
    }
}
