use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::RiskTag::{Hosting, Other, Proxy, Tor};
use crate::ip_check::ip_result::{
    AS, Coordinates, IpResult, Region, Risk, create_reqwest_client_error,
    json_parse_error_ip_result, not_support_error, request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct IpLarkComIpData;

#[async_trait]
impl IpCheck for IpLarkComIpData {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            vec![not_support_error("IpLark.com IpData")]
        } else {
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v4) = create_reqwest_client(None, Some(false)).await else {
                    return create_reqwest_client_error("IpLark.com IpData");
                };

                let Ok(result) = client_v4
                    .get("https://iplark.com/ipapi/public/ipinfo?db=ipdata")
                    .send()
                    .await
                else {
                    return request_error_ip_result("IpLark.com IpData", "Unable to connect");
                };

                let mut result_without_time = parse_ip_lark_com_ipdata(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v6) = create_reqwest_client(None, Some(true)).await else {
                    return create_reqwest_client_error("IpLark.com IpData");
                };

                let Ok(result) = client_v6
                    .get("https://6.iplark.com/ipapi/public/ipinfo?db=ipdata")
                    .send()
                    .await
                else {
                    return request_error_ip_result("IpLark.com IpData", "Unable to connect");
                };

                let mut result_without_time = parse_ip_lark_com_ipdata(result).await;
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

async fn parse_ip_lark_com_ipdata(response: Response) -> IpResult {
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

    let Ok(json) = response.json::<IpLarkComIpDataResp>().await else {
        return json_parse_error_ip_result(
            "IpLark.com IpData",
            "Unable to parse the returned result into Json",
        );
    };

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
        risk_tags.push(Other("Bogon".to_string()));
    }

    let score = json.threat.scores.trust_score.map(|score| 100 - score);

    let asn = if let Some(asn) = json.asn.asn {
        asn.replace("AS", "").parse::<u32>().ok()
    } else {
        None
    };

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
