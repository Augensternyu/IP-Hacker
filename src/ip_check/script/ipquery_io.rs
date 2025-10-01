// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::RiskTag::{Hosting, Mobile, Proxy, Tor}; // 引入风险标签
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, parse_ip_error_ip_result, request_error_ip_result, Coordinates, IpResult,
    Region, Risk, AS,
}; // 引入IP检查结果相关的结构体和函数
use crate::ip_check::script::create_reqwest_client; // 引入创建 reqwest 客户端的函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use serde::{Deserialize, Serialize}; // 引入 serde 的 Deserialize 和 Serialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 IpQueryIo 结构体
pub struct IpQueryIo;

// 为 IpQueryIo 实现 IpCheck trait
#[async_trait]
impl IpCheck for IpQueryIo {
    // 异步检查 IP 地址
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            // --- 检查指定IP ---
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client) = create_reqwest_client(None).await else {
                    return create_reqwest_client_error("Ipquery.io");
                };

                let Ok(result) = client
                    .get(format!("https://api.ipquery.io/{ip}?format=json"))
                    .send()
                    .await
                else {
                    return request_error_ip_result(
                        "Ipquery.io",
                        "Unable to connect to ipquery.io",
                    );
                };

                let Ok(json) = result.json::<serde_json::Value>().await else {
                    return parse_ip_error_ip_result("Ipquery.io", "Unable to parse json");
                };

                let mut result_without_time = get_ipquery_io_info(json);
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time); // 记录耗时
                result_without_time
            });
            vec![handle.await.unwrap_or(json_parse_error_ip_result(
                "Ipquery.io",
                "Unable to parse json",
            ))]
        } else {
            // --- 检查本机IP (v4 和 v6) ---
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("Ipquery.io");
                };

                let Ok(result) = client_v4
                    .get("https://api.ipquery.io/?format=json")
                    .send()
                    .await
                else {
                    return request_error_ip_result("Ipquery.io", "Unable to connect");
                };

                let Ok(json) = result.json::<serde_json::Value>().await else {
                    return parse_ip_error_ip_result("Ipquery.io", "Unable to parse json");
                };

                let mut result_without_time = get_ipquery_io_info(json);
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error("Ipquery.io");
                };

                let Ok(result) = client_v6
                    .get("https://api.ipquery.io/?format=json")
                    .send()
                    .await
                else {
                    return request_error_ip_result("Ipquery.io", "Unable to connect");
                };

                let Ok(json) = result.json::<serde_json::Value>().await else {
                    return parse_ip_error_ip_result("Ipquery.io", "Unable to parse json");
                };

                let mut result_without_time = get_ipquery_io_info(json);
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            let mut results = Vec::new();
            if let Ok(result) = handle_v4.await {
                results.push(result);
            }
            if let Ok(result) = handle_v6.await {
                results.push(result);
            }
            results
        }
    }
}

// 解析 Ipquery.io 的 API 响应
fn get_ipquery_io_info(json: serde_json::Value) -> IpResult {
    // 定义用于解析 JSON 响应的内部结构体
    #[derive(Debug, Serialize, Deserialize)]
    struct IpQuery {
        ip: Option<IpAddr>,
        isp: Isp,
        location: Location,
        risk: Risks,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct Isp {
        asn: Option<String>,
        name: Option<String>,
        org: Option<String>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct Location {
        city: Option<String>,
        country: Option<String>,
        latitude: Option<f64>,
        longitude: Option<f64>,
        state: Option<String>,
        timezone: Option<String>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct Risks {
        is_datacenter: Option<bool>,
        is_mobile: Option<bool>,
        is_proxy: Option<bool>,
        is_tor: Option<bool>,
        is_vpn: Option<bool>,
        risk_score: Option<u16>,
    }

    // 将 Value 解析为 IpQuery 结构体
    let Ok(json_parsed) = serde_json::from_value::<IpQuery>(json) else {
        return parse_ip_error_ip_result("Ipquery.io", "Unable to parse json");
    };

    // 解析风险标签
    let mut risk_tags = vec![];
    if json_parsed.risk.is_datacenter.unwrap_or(false) {
        risk_tags.push(Hosting);
    }
    if json_parsed.risk.is_mobile.unwrap_or(false) {
        risk_tags.push(Mobile);
    }
    if json_parsed.risk.is_proxy.unwrap_or(false) {
        risk_tags.push(Proxy);
    }
    if json_parsed.risk.is_tor.unwrap_or(false) {
        risk_tags.push(Tor);
    }
    if json_parsed.risk.is_vpn.unwrap_or(false) {
        risk_tags.push(Proxy); // VPN 归类为代理
    }

    // 构建并返回 IpResult
    IpResult {
        success: true,
        error: No,
        provider: "Ipquery.io".to_string(),
        ip: json_parsed.ip,
        autonomous_system: {
            let asn = json_parsed
                .isp
                .asn
                .map(|asn| asn.replace("AS", "").parse::<u32>().unwrap_or(0));
            let isp = json_parsed.isp.name;
            if let (Some(asn), Some(isp)) = (asn, isp) {
                Some(AS {
                    number: asn,
                    name: isp,
                })
            } else {
                None
            }
        },
        region: Some(Region {
            country: json_parsed.location.country,
            province: json_parsed.location.state,
            city: json_parsed.location.city,
            coordinates: {
                let latitude = json_parsed.location.latitude;
                let longitude = json_parsed.location.longitude;
                if let (Some(latitude), Some(longitude)) = (latitude, longitude) {
                    Some(Coordinates {
                        latitude: latitude.to_string(),
                        longitude: longitude.to_string(),
                    })
                } else {
                    None
                }
            },
            time_zone: json_parsed.location.timezone,
        }),
        risk: Some(Risk {
            risk: json_parsed.risk.risk_score,
            tags: Some(risk_tags),
        }),
        used_time: None, // 耗时将在调用处设置
    }
}
