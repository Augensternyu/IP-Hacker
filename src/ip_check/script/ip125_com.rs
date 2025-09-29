// src/ip_check/script/ip125_com.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, request_error_ip_result, Coordinates, IpResult, Region,
    AS,
}; // 引入错误处理函数和结果结构体
use crate::ip_check::script::create_reqwest_client; // 引入 reqwest 客户端创建函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use regex::Regex; // 引入 regex 库用于正则表达式
use reqwest::Response; // 引入 reqwest 的 Response
use serde::{Deserialize, Serialize}; // 引入 serde 的 Deserialize 和 Serialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 Ip125Com 结构体
pub struct Ip125Com;

// 定义常量
const PROVIDER_NAME: &str = "Ip125.com"; // 提供商名称
const API_BASE_URL: &str = "https://ip125.com/api/"; // API 基础 URL (API 本身只支持 IPv4 访问)

// --- 用于反序列化 API JSON 响应的结构体 ---
#[derive(Deserialize, Serialize, Debug)]
struct Ip125ComApiRespPayload {
    status: String,
    country: Option<String>,
    #[serde(rename = "countryCode")]
    country_code: Option<String>, // 未直接在 IpResult 中使用，但保留以备将来之需
    region: Option<String>, // 区域代码，例如 "QC"
    #[serde(rename = "regionName")]
    region_name: Option<String>, // 完整的区域名称
    city: Option<String>,
    // zip: Option<String>, // 未使用
    lat: Option<f64>,
    lon: Option<f64>,
    timezone: Option<String>,
    isp: Option<String>,
    org: Option<String>, // 通常与 ISP 类似或是其母公司
    #[serde(rename = "as")]
    asn_str: Option<String>, // 例如 "AS13335 Cloudflare, Inc."
    query: String,       // 被查询的 IP 地址
    message: Option<String>, // 用于错误信息，例如 "invalid query"
}

// 清理字符串字段，去除无效值
fn sanitize_string_field(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty()
            || trimmed == "-"
            || trimmed == "未知"
            || trimmed.to_lowercase() == "unknown"
        {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

// 从字符串中解析 ASN 编号和名称
fn parse_asn_from_string(asn_string_opt: Option<String>) -> (Option<u32>, Option<String>) {
    match asn_string_opt {
        Some(asn_string) => {
            let re = Regex::new(r"^(AS)?(\d+)\s*(.*)$").unwrap(); // 使 "AS" 前缀可选
            if let Some(caps) = re.captures(&asn_string) {
                let number = caps.get(2).and_then(|m| m.as_str().parse::<u32>().ok());
                let name = caps
                    .get(3)
                    .map(|m| m.as_str().trim().to_string())
                    .filter(|s| !s.is_empty());
                (number, name)
            } else {
                // 如果正则表达式不匹配，且字符串不完全是数字，则将其视为名称
                if asn_string.chars().all(char::is_numeric) {
                    (asn_string.parse::<u32>().ok(), None)
                } else {
                    (None, Some(asn_string))
                }
            }
        }
        None => (None, None),
    }
}

// 为 Ip125Com 实现 IpCheck trait
#[async_trait]
impl IpCheck for Ip125Com {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        // API 本身通过 IPv4 访问，但可以查询 IPv4 或 IPv6 的数据
        let client = match create_reqwest_client(Some(false)).await {
            // 强制使用 IPv4 访问 API
            Ok(c) => c,
            Err(_) => return vec![create_reqwest_client_error(PROVIDER_NAME)],
        };

        // 根据是否提供 IP 构建 URL
        let url = if let Some(ip_addr) = ip {
            format!("{}{}{}", API_BASE_URL, ip_addr, "?lang=zh-CN")
        } else {
            // 对于本机 IP，API 端点就是基础 URL
            // API 会自动检测客户端的 IP (由于我们的客户端配置，这将是 IPv4)
            format!("{}{}", API_BASE_URL, "?lang=zh-CN")
        };

        // 异步执行查询
        let handle = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();

            let response = match client.get(&url).send().await {
                Ok(r) => r,
                Err(e) => return request_error_ip_result(PROVIDER_NAME, &e.to_string()),
            };

            let mut result_without_time = parse_ip125_com_resp(response).await;
            result_without_time.used_time = Some(time_start.elapsed());
            result_without_time
        });

        // 等待并返回结果
        match handle.await {
            Ok(result) => vec![result], // 此 API 每个请求返回一个结果
            Err(_) => vec![request_error_ip_result(
                PROVIDER_NAME,
                "Task panicked or was cancelled.",
            )],
        }
    }
}

// 解析 Ip125.com 的 API 响应
async fn parse_ip125_com_resp(response: Response) -> IpResult {
    if !response.status().is_success() {
        let err_msg = format!("HTTP Error: {}", response.status());
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
    let payload: Ip125ComApiRespPayload = match serde_json::from_str(&response_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = response_text.chars().take(100).collect::<String>();
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse JSON: {e}. Response snippet: '{snippet}'"),
            );
        }
    };

    // 检查 API 返回的状态
    if payload.status != "success" {
        let err_msg = payload
            .message
            .unwrap_or_else(|| "API status was not 'success'.".to_string());
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
    }

    // 解析查询的 IP 地址
    let parsed_ip = match payload.query.parse::<IpAddr>() {
        Ok(ip_addr) => ip_addr,
        Err(_) => {
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse 'query' IP from API: '{}'", payload.query),
            );
        }
    };

    // 清理地理位置信息
    let country = sanitize_string_field(payload.country);
    let region_name = sanitize_string_field(payload.region_name);
    let city = sanitize_string_field(payload.city);
    let timezone = sanitize_string_field(payload.timezone);

    // 解析 ASN 信息
    let (asn_number, asn_name_from_as_field) =
        parse_asn_from_string(sanitize_string_field(payload.asn_str));

    let isp_name = sanitize_string_field(payload.isp);
    let org_name = sanitize_string_field(payload.org);

    // 优先使用 ISP，然后是 ORG，最后是 'as' 字段中的名称作为 AS 名称
    let final_as_name = isp_name.or(org_name).or(asn_name_from_as_field);

    let autonomous_system = final_as_name.map(|name| AS {
        number: asn_number.unwrap_or(0),
        name,
    });

    // 解析坐标
    let coordinates = match (payload.lat, payload.lon) {
        (Some(lat), Some(lon)) => Some(Coordinates {
            lat: lat.to_string(),
            lon: lon.to_string(),
        }),
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
            region: region_name, // 使用 regionName，因为它更具描述性
            city,
            coordinates,
            time_zone: timezone,
        }),
        risk: None,      // API 不提供风险信息
        used_time: None, // 将由调用者设置
    }
}
