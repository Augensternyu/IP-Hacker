use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::RiskTag::{Hosting, Other, Proxy, Tor};
use crate::ip_check::ip_result::{
    AS, Coordinates, IpResult, Region, Risk, create_reqwest_client_error,
    json_parse_error_ip_result, request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct IpdataCo;

const API_KEY: &str = "a4098f89e8ceb83ca53f144e14088a4f1407aabb77d9b479b3a3b005";

#[async_trait]
impl IpCheck for IpdataCo {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        // 由于API不支持IPv6访问，我们只创建一个强制使用IPv4的handle
        if let Some(ip) = ip {
            // --- 检查指定IP ---
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // 强制使用IPv4进行API访问
                let Ok(client) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("IpData.co");
                };

                let url = format!("https://api.ipdata.co/{ip}?api-key={API_KEY}");
                let Ok(result) = client.get(url).send().await else {
                    return request_error_ip_result("IpData.co", "Unable to connect");
                };

                let mut result_without_time = parse_ipdata_co_resp(result).await;
                result_without_time.used_time = Some(time_start.elapsed());
                result_without_time
            });
            vec![handle.await.unwrap()]
        } else {
            // --- 检查本机IP ---
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // 强制使用IPv4进行API访问
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("IpData.co");
                };

                let url = format!("https://api.ipdata.co/?api-key={API_KEY}");
                let Ok(result) = client_v4.get(url).send().await else {
                    return request_error_ip_result("IpData.co", "Unable to connect");
                };

                let mut result_without_time = parse_ipdata_co_resp(result).await;
                result_without_time.used_time = Some(time_start.elapsed());
                result_without_time
            });

            vec![handle_v4.await.unwrap()]
        }
    }
}

async fn parse_ipdata_co_resp(response: Response) -> IpResult {
    #[derive(Deserialize, Serialize)]
    struct Resp {
        ip: Option<IpAddr>,
        city: Option<String>,
        region: Option<String>,
        country_name: Option<String>,
        latitude: Option<f64>,
        longitude: Option<f64>,
        asn: Option<AsnData>,
        time_zone: Option<TimeZoneData>,
        threat: Option<ThreatData>,
        message: Option<String>, // 用于捕获API的错误信息
    }
    #[derive(Deserialize, Serialize)]
    struct AsnData {
        asn: Option<String>,
        name: Option<String>,
    }
    #[derive(Deserialize, Serialize)]
    struct TimeZoneData {
        name: Option<String>,
    }
    #[derive(Deserialize, Serialize)]
    struct ThreatData {
        is_tor: Option<bool>,
        is_icloud_relay: Option<bool>,
        is_proxy: Option<bool>,
        is_datacenter: Option<bool>,
        is_anonymous: Option<bool>,
        is_known_attacker: Option<bool>,
        is_known_abuser: Option<bool>,
        is_threat: Option<bool>,
        is_bogon: Option<bool>,
    }

    let Ok(json) = response.json::<Resp>().await else {
        return json_parse_error_ip_result("IpData.co", "Unable to parse result into Json");
    };

    if let Some(msg) = json.message {
        return request_error_ip_result("IpData.co", &msg);
    }
    if json.ip.is_none() {
        return request_error_ip_result("IpData.co", "API response did not contain an IP address.");
    }

    let mut risk_tags = Vec::new();
    if let Some(threat) = json.threat {
        if threat.is_tor.unwrap_or(false) {
            risk_tags.push(Tor);
        }
        if threat.is_proxy.unwrap_or(false) {
            risk_tags.push(Proxy);
        }
        if threat.is_icloud_relay.unwrap_or(false) {
            risk_tags.push(Other("iCLOUD RELAY".to_string()));
        }
        if threat.is_datacenter.unwrap_or(false) {
            risk_tags.push(Hosting);
        }
        if threat.is_anonymous.unwrap_or(false) {
            risk_tags.push(Other("ANONYMOUS".to_string()));
        }
        if threat.is_known_attacker.unwrap_or(false) {
            risk_tags.push(Other("ATTACKER".to_string()));
        }
        if threat.is_known_abuser.unwrap_or(false) {
            risk_tags.push(Other("ABUSER".to_string()));
        }
        if threat.is_threat.unwrap_or(false) {
            risk_tags.push(Other("THREAT".to_string()));
        }
        if threat.is_bogon.unwrap_or(false) {
            risk_tags.push(Other("BOGON".to_string()));
        }
    }

    let asn_details = json.asn.as_ref();
    let asn_num = asn_details
        .and_then(|a| a.asn.as_ref())
        .and_then(|s| s.strip_prefix("AS"))
        .and_then(|num_str| num_str.parse::<u32>().ok());
    let isp_name = asn_details.and_then(|a| a.name.clone());

    IpResult {
        success: true,
        error: No,
        provider: "IpData.co".to_string(),
        ip: json.ip,
        autonomous_system: {
            if let (Some(number), Some(name)) = (asn_num, isp_name) {
                Some(AS { number, name })
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
            time_zone: json.time_zone.and_then(|tz| tz.name),
        }),
        risk: Some(Risk {
            risk: None, // API不提供风险分数
            tags: Some(risk_tags),
        }),
        used_time: None,
    }
}
