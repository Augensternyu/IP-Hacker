// src/ip_check/script/ipw_cn.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::{self, No}; // 引入错误枚举和无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, not_support_error, parse_ip_error_ip_result, request_error_ip_result, Coordinates,
    IpResult, Region, AS,
}; // 引入IP检查结果相关的结构体和函数
use crate::ip_check::script::create_reqwest_client; // 引入创建 reqwest 客户端的函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use serde::{Deserialize, Serialize}; // 引入 serde 的 Deserialize 和 Serialize
use std::net::{IpAddr, Ipv6Addr}; // 引入 IpAddr 和 Ipv6Addr

// 定义 IpwCn 结构体
pub struct IpwCn;

// 定义提供商名称
const PROVIDER_NAME: &str = "Ipw.cn";

// 定义用于解析本机 IP 响应的结构体
#[derive(Deserialize, Serialize, Debug)]
struct IpwCnMyIpResp {
    #[serde(rename = "result")]
    _result: bool, // 不直接使用，解析成功即表示成功
    #[serde(rename = "IP")]
    ip: Option<String>,
    #[serde(rename = "IPVersion")]
    ip_version: Option<String>,
    // message: Option<String>,
    // code: Option<String>,
}

// 定义用于解析 IP 详情 API 数据部分的结构体
#[derive(Deserialize, Serialize, Debug)]
struct IpwCnApiDataPayload {
    continent: Option<String>,
    country: Option<String>,
    // zipcode: Option<String>,
    timezone: Option<String>,
    // accuracy: Option<String>,
    // owner: Option<String>, // 通常与 ISP 重复或信息较少
    isp: Option<String>,
    // source: Option<String>,
    // areacode: Option<String>,
    // adcode: Option<String>,
    asnumber: Option<String>, // 字符串 "9808"
    lat: Option<String>,
    lng: Option<String>,
    // radius: Option<String>,
    prov: Option<String>,
    city: Option<String>,
    district: Option<String>,
    // currency_code: Option<String>,
    // currency_name: Option<String>,
}

// 定义用于解析 IP 详情 API 响应的结构体
#[derive(Deserialize, Serialize, Debug)]
struct IpwCnApiRespPayload {
    code: String, // "Success" 或其他错误码
    data: Option<IpwCnApiDataPayload>,
    // charge: bool,
    msg: Option<String>,
    ip: Option<String>, // 查询的 IP
    // coordsys: Option<String>,
}

// 异步获取并解析 IP 详情
async fn fetch_and_parse_ip_details(client: &reqwest::Client, target_ip: Ipv6Addr) -> IpResult {
    let url = format!(
        "https://rest.ipw.cn/api/aw/v1/ipv6?ip={target_ip}&warning=please-direct-use-please-use-ipplus360.com"
    );

    let response = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            return request_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to connect to details API: {e}"),
            );
        }
    };

    if !response.status().is_success() {
        return request_error_ip_result(
            PROVIDER_NAME,
            &format!("Details API HTTP Error: {}", response.status()),
        );
    }

    let response_text = match response.text().await {
        Ok(text) => text,
        Err(e) => {
            return request_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to read details response text: {e}"),
            );
        }
    };

    let payload: IpwCnApiRespPayload = match serde_json::from_str(&response_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = response_text.chars().take(100).collect::<String>();
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse details JSON: {e}. Response snippet: '{snippet}'"),
            );
        }
    };

    if payload.code.to_lowercase() != "success" {
        let err_msg = payload
            .msg
            .unwrap_or_else(|| format!("API error code: {}", payload.code));
        let mut err_res = request_error_ip_result(PROVIDER_NAME, &err_msg);
        // 即使出错，也尝试包含 API 返回的 IP 地址
        if let Some(ip_str) = payload.ip.as_deref() {
            err_res.ip = ip_str.parse::<IpAddr>().ok();
        }
        return err_res;
    }

    let data = match payload.data {
        Some(d) => d,
        None => {
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                "Details API success but 'data' field is missing.",
            );
        }
    };

    // 确保响应中的 IP 与查询的 IP 匹配，或可解析
    let final_ip_addr = match payload.ip.as_deref().map(str::parse::<IpAddr>) {
        Some(Ok(ip)) => ip,
        _ => IpAddr::V6(target_ip), // 回退到我们打算查询的 IP
    };

    // 这是一个仅支持 IPv6 的 API，如果 final_ip_addr 不是 V6，则说明有问题
    if !final_ip_addr.is_ipv6() {
        return parse_ip_error_ip_result(
            PROVIDER_NAME,
            "Details API returned a non-IPv6 address for an IPv6 query.",
        );
    }

    let as_number = data.asnumber.and_then(|s| s.parse::<u32>().ok());

    IpResult {
        success: true,
        error: No,
        provider: PROVIDER_NAME.to_string(),
        ip: Some(final_ip_addr),
        autonomous_system: match (as_number, data.isp) {
            (Some(num), Some(name)) => Some(AS { number: num, name }),
            (None, Some(name)) => Some(AS { number: 0, name }), // 有 ISP 名称但没有 ASN
            _ => None,
        },
        region: Some(Region {
            country: data.country,
            region: data.prov,
            city: data.city.or(data.district), // 优先使用 city，回退到 district
            coordinates: match (data.lat, data.lng) {
                (Some(lat_str), Some(lon_str)) => Some(Coordinates {
                    lat: lat_str,
                    lon: lon_str,
                }),
                _ => None,
            },
            time_zone: data.timezone,
        }),
        risk: None,      // API 不提供直接的风险标志
        used_time: None, // 将由调用者设置
    }
}

// 为 IpwCn 实现 IpCheck trait
#[async_trait]
impl IpCheck for IpwCn {
    // 异步检查 IP 地址
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        let target_ipv6_opt: Option<Ipv6Addr> = match ip {
            Some(IpAddr::V6(ipv6_addr)) => Some(ipv6_addr),
            Some(IpAddr::V4(_)) => {
                // API 仅支持 IPv6 详情查询
                return vec![not_support_error(PROVIDER_NAME)];
            }
            None => {
                // 需要获取本机 IPv6
                let client_for_myip = match create_reqwest_client(Some(true)).await {
                    // 必须使用 IPv6 客户端
                    Ok(c) => c,
                    Err(_) => return vec![create_reqwest_client_error(PROVIDER_NAME)],
                };
                match client_for_myip
                    .get("https://6.ipw.cn/api/ip/myip?json")
                    .send()
                    .await
                {
                    Ok(resp) => {
                        if !resp.status().is_success() {
                            return vec![request_error_ip_result(
                                PROVIDER_NAME,
                                &format!("myip API HTTP Error: {}", resp.status()),
                            )];
                        }
                        match resp.json::<IpwCnMyIpResp>().await {
                            Ok(my_ip_payload) => {
                                if my_ip_payload.ip_version.as_deref() == Some("IPv6") {
                                    my_ip_payload.ip.and_then(|s| s.parse::<Ipv6Addr>().ok())
                                } else {
                                    None // 不是 IPv6 地址或版本不匹配
                                }
                            }
                            Err(e) => {
                                return vec![json_parse_error_ip_result(
                                    PROVIDER_NAME,
                                    &format!("Failed to parse myip JSON: {e}"),
                                )];
                            }
                        }
                    }
                    Err(e) => {
                        return vec![request_error_ip_result(
                            PROVIDER_NAME,
                            &format!("Failed to connect to myip API: {e}"),
                        )];
                    }
                }
            }
        };

        let target_ipv6 = if let Some(ipv6) = target_ipv6_opt {
            ipv6
        } else {
            // 如果 'ip' 为 None 且无法获取本机 IPv6，则无法继续
            let mut res = not_support_error(PROVIDER_NAME);
            res.error = IpCheckError::Request(
                "Could not determine a local IPv6 address to query.".to_string(),
            );
            return vec![res];
        };

        // 现在使用确定的 target_ipv6 查询详情
        let handle = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            // 根据问题描述，为详情 API 使用默认客户端 ("请求使用ipv6与否默认即可")
            // 然而，由于 API 本身是 IPv6 特定的 (rest.ipw.cn/api/aw/v1/ipv6)，
            // 如果主机有 IPv6，可能隐式需要一个可以发出 IPv6 请求的客户端。
            // 使用 `None` for create_reqwest_client 是 "默认"。
            let client_for_details = match create_reqwest_client(None).await {
                Ok(c) => c,
                Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
            };

            let mut result_without_time =
                fetch_and_parse_ip_details(client_for_details, target_ipv6).await;
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
