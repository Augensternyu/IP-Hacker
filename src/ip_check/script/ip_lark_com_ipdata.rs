// src/ip_check/script/ip_lark_com_ipdata.rs

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
use std::net::IpAddr; // 引入 IpAddr

// 定义 IpLarkComIpData 结构体
pub struct IpLarkComIpData;

// 为 IpLarkComIpData 实现 IpCheck trait
#[async_trait]
impl IpCheck for IpLarkComIpData {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            // 此 API 不支持查询指定 IP
            vec![not_support_error("IpLark.com IpData")]
        } else {
            // 异步查询 IPv4 地址
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // 创建仅使用 IPv4 的 reqwest 客户端
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("IpLark.com IpData");
                };

                // 发送 GET 请求
                let Ok(result) = client_v4
                    .get("https://iplark.com/ipapi/public/ipinfo?db=ipdata")
                    .send()
                    .await
                else {
                    return request_error_ip_result("IpLark.com IpData", "Unable to connect");
                };

                // 解析响应并计算耗时
                let mut result_without_time = parse_ip_lark_com_ipdata(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            // 异步查询 IPv6 地址
            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // 创建仅使用 IPv6 的 reqwest 客户端
                let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error("IpLark.com IpData");
                };

                // 发送 GET 请求
                let Ok(result) = client_v6
                    .get("https://6.iplark.com/ipapi/public/ipinfo?db=ipdata")
                    .send()
                    .await
                else {
                    return request_error_ip_result("IpLark.com IpData", "Unable to connect");
                };

                // 解析响应并计算耗时
                let mut result_without_time = parse_ip_lark_com_ipdata(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            // 等待并收集结果
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

// 解析 IpLark.com IpData 的 API 响应
async fn parse_ip_lark_com_ipdata(response: Response) -> IpResult {
    // 定义用于反序列化 API 响应的结构体
    #[derive(Deserialize, Serialize)]
    struct IpLarkComIpDataResp {
        ip: IpAddr,
        city: Option<String>,
        region: Option<String>,
        country_name: Option<String>,
        latitude: Option<f64>,
        longitude: Option<f64>,
        asn: ASN,
        time_zone: TimeZone,
        threat: Threat,
    }
    #[derive(Deserialize, Serialize)]
    struct ASN {
        asn: Option<String>,
        name: Option<String>,
    }
    #[derive(Deserialize, Serialize)]
    struct TimeZone {
        name: Option<String>,
    }
    #[derive(Deserialize, Serialize)]
    struct Threat {
        is_tor: Option<bool>,
        is_vpn: Option<bool>,
        is_icloud_relay: Option<bool>,
        is_proxy: Option<bool>,
        is_datacenter: Option<bool>,
        is_anonymous: Option<bool>,
        is_known_attacker: Option<bool>,
        is_known_abuser: Option<bool>,
        is_threat: Option<bool>,
        is_bogon: Option<bool>,
        scores: Scores,
    }
    #[derive(Deserialize, Serialize)]
    struct Scores {
        trust_score: Option<u16>,
    }

    // 将响应体解析为 JSON
    let Ok(json) = response.json::<IpLarkComIpDataResp>().await else {
        return json_parse_error_ip_result(
            "IpLark.com IpData",
            "Unable to parse the returned result into Json",
        );
    };

    // 解析风险标签
    let mut risk_tags = Vec::new();
    if let Some(true) = json.threat.is_tor {
        risk_tags.push(Tor);
    }
    if let Some(true) = json.threat.is_proxy {
        risk_tags.push(Proxy);
    }
    if let Some(true) = json.threat.is_icloud_relay {
        risk_tags.push(Other("iCloud RELAY".to_string()));
    }
    if let Some(true) = json.threat.is_proxy {
        risk_tags.push(Proxy);
    }
    if let Some(true) = json.threat.is_datacenter {
        risk_tags.push(Hosting);
    }
    if let Some(true) = json.threat.is_anonymous {
        risk_tags.push(Other("ANONYMOUS".to_string()));
    }
    if let Some(true) = json.threat.is_known_attacker {
        risk_tags.push(Other("ATTACKER".to_string()));
    }
    if let Some(true) = json.threat.is_known_abuser {
        risk_tags.push(Other("ABUSER".to_string()));
    }
    if let Some(true) = json.threat.is_threat {
        risk_tags.push(Other("THREAT".to_string()));
    }
    if let Some(true) = json.threat.is_bogon {
        risk_tags.push(Other("BOGON".to_string()));
    }

    // 计算风险评分
    let score = json.threat.scores.trust_score.map(|score| 100 - score);

    // 解析 ASN
    let asn = if let Some(asn) = json.asn.asn {
        asn.replace("AS", "").parse::<u32>().ok()
    } else {
        None
    };

    // 构建 IpResult
    IpResult {
        success: true,
        error: No,
        provider: "IpLark.com IpData".to_string(),
        ip: Some(json.ip),
        autonomous_system: {
            if let (Some(asn), Some(isp)) = (asn, json.asn.name) {
                Some(AS {
                    number: asn,
                    name: isp,
                })
            } else {
                None
            }
        },
        region: Some(Region {
            country: json.country_name,
            region: json.region,
            city: json.city,
            coordinates: if let (Some(lat), Some(lon)) = (json.latitude, json.longitude) {
                Some(Coordinates {
                    lat: lat.to_string(),
                    lon: lon.to_string(),
                })
            } else {
                None
            },
            time_zone: json.time_zone.name,
        }),
        risk: Some(Risk {
            risk: score,
            tags: Some(risk_tags),
        }),
        used_time: None,
    }
}
