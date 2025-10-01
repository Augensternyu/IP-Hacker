// src/ip_check/script/cz88_net.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::RiskTag::{Hosting, Other, Proxy, Tor}; // 引入风险标签
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, not_support_error, request_error_ip_result, Coordinates, IpResult,
    Region, Risk, AS,
}; // 引入错误处理函数和结果结构体
use crate::ip_check::script::create_reqwest_client; // 引入 reqwest 客户端创建函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use serde::{Deserialize, Serialize}; // 引入 serde 的 Deserialize 和 Serialize
use std::collections::HashSet; // 引入 HashSet
use std::net::IpAddr; // 引入 IpAddr

// 定义 Cz88Net 结构体
pub struct Cz88Net;

// 定义常量
const PROVIDER_NAME: &str = "Cz88.net"; // 提供商名称

// --- 用于反序列化 API JSON 响应的结构体 ---

#[derive(Deserialize, Serialize, Debug)]
struct Cz88NetApiLocation {
    latitude: Option<String>,
    longitude: Option<String>,
    // radius: Option<u32>, // 未使用
}

#[derive(Deserialize, Serialize, Debug)]
struct Cz88NetApiDataPayload {
    ip: String,
    country: Option<String>,
    province: Option<String>,
    city: Option<String>,
    isp: Option<String>,
    asn: Option<String>,     // 更像是一个标签或组织名称
    company: Option<String>, // 也是一个组织名称
    locations: Option<Vec<Cz88NetApiLocation>>,
    score: Option<String>, // 信任分数，字符串 "0"-"100"
    vpn: Option<bool>,
    tor: Option<bool>,
    proxy: Option<bool>,
    #[serde(rename = "icloudPrivateRelay")]
    icloud_private_relay: Option<bool>,
    #[serde(rename = "netWorkType")]
    net_work_type: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
struct Cz88NetApiRespPayload {
    code: i32,
    success: bool,
    message: Option<String>,
    data: Option<Cz88NetApiDataPayload>,
    // time: Option<String>, // 未使用
}

// 清理字符串字段，去除首尾空格和无效值
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

// 为 Cz88Net 实现 IpCheck trait
#[async_trait]
impl IpCheck for Cz88Net {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        let Some(ip_addr) = ip else {
            return vec![not_support_error(PROVIDER_NAME)];
        }; // API 需要指定 IP

        let handle = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();

            // 创建 reqwest 客户端
            let Ok(client) = create_reqwest_client(None).await else {
                return create_reqwest_client_error(PROVIDER_NAME);
            };

            // 发送 GET 请求
            let url = format!("https://update.cz88.net/api/cz88/ip/base?ip={ip_addr}");
            let response = match client.get(url).send().await {
                Ok(r) => r,
                Err(e) => return request_error_ip_result(PROVIDER_NAME, &e.to_string()),
            };

            // 解析响应并计算耗时
            let mut result_without_time = parse_cz88_net_resp(response, ip_addr).await;
            result_without_time.used_time = Some(time_start.elapsed());
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

// 解析 Cz88.net 的 API 响应
async fn parse_cz88_net_resp(response: Response, _original_ip: IpAddr) -> IpResult {
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
    let payload: Cz88NetApiRespPayload = match serde_json::from_str(&response_text) {
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
    if !(payload.code == 200 && payload.success) {
        let err_msg = payload
            .message
            .unwrap_or_else(|| "API indicated failure.".to_string());
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
    }

    // 获取数据部分
    let Some(ref data) = payload.data else {
        return json_parse_error_ip_result(
            PROVIDER_NAME,
            "API success but 'data' field is missing.",
        );
    };

    // 解析 IP 地址
    let Ok(parsed_ip) = data.ip.parse::<IpAddr>() else {
        return json_parse_error_ip_result(
            PROVIDER_NAME,
            &format!("Failed to parse IP string from API data: '{}'", data.ip),
        );
    };

    // 清理地理位置信息
    let country = sanitize_string_field(data.country.clone());
    let province = sanitize_string_field(data.province.clone());
    let city = sanitize_string_field(data.city.clone());

    let autonomous_system = parse_autonomous_system(data);
    let coordinates = parse_coordinates(data);
    let risk_score = parse_risk_score(data);
    let risk_tags_vec = parse_risk_tags(data);


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
            time_zone: None, // API 不提供时区
        }),
        risk: Some(Risk {
            risk: risk_score,
            tags: if risk_tags_vec.is_empty() {
                None
            } else {
                Some(risk_tags_vec)
            },
        }),
        used_time: None,
    }
}

fn parse_risk_tags(data: &Cz88NetApiDataPayload) -> Vec<RiskTag> {
    let mut risk_tags_set = HashSet::new();
    if data.vpn == Some(true) {
        risk_tags_set.insert(Proxy);
    }
    if data.tor == Some(true) {
        risk_tags_set.insert(Tor);
    }
    if data.proxy == Some(true) {
        risk_tags_set.insert(Proxy);
    }
    if data.icloud_private_relay == Some(true) {
        risk_tags_set.insert(Other("iCloud Relay".to_string()));
    }
    if let Some(net_type) = sanitize_string_field(data.net_work_type.clone())
        && net_type == "数据中心" {
            risk_tags_set.insert(Hosting);
        }
    risk_tags_set.into_iter().collect()
}

fn parse_autonomous_system(data: &Cz88NetApiDataPayload) -> Option<AS> {
    let isp_name_opt = sanitize_string_field(data.isp.clone());
    let company_name_opt = sanitize_string_field(data.company.clone());
    let asn_label_opt = sanitize_string_field(data.asn.clone());

    let as_name = isp_name_opt.or(company_name_opt).or(asn_label_opt);

    as_name.map(|name| AS {
        number: 0, // API 不提供 ASN 号码
        name,
    })
}

fn parse_coordinates(data: &Cz88NetApiDataPayload) -> Option<Coordinates> {
    data.locations.as_ref().and_then(|locs| {
        locs.first().and_then(|loc| {
            match (
                sanitize_string_field(loc.latitude.clone()),
                sanitize_string_field(loc.longitude.clone()),
            ) {
                (Some(latitude), Some(longitude)) => Some(Coordinates { latitude, longitude }),
                _ => None,
            }
        })
    })
}

fn parse_risk_score(data: &Cz88NetApiDataPayload) -> Option<u16> {
    data
        .score
        .as_ref()
        .and_then(|s| s.parse::<u16>().ok())
        .map(|trust_score| {
            if trust_score > 100 {
                100
            } else {
                100 - trust_score
            } // 将信任分数转换为风险分数
        })
}
