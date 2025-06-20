use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::RiskTag::{Hosting, Mobile, Proxy, Tor};
use crate::ip_check::ip_result::{
    AS, Coordinates, IpResult, Region, Risk, create_reqwest_client_error,
    json_parse_error_ip_result, parse_ip_error_ip_result, request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct IpQueryIo;

#[async_trait]
impl IpCheck for IpQueryIo {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            let handle = tokio::spawn(async move {
                let Ok(client) = create_reqwest_client(Some("curl/8.11.1"), None).await else {
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

                get_ipquery_io_info(json).await
            });
            vec![handle.await.unwrap_or(json_parse_error_ip_result(
                "Ipquery.io",
                "Unable to parse json",
            ))]
        } else {
            let handle_v4 = tokio::spawn(async move {
                let Ok(client_v4) = create_reqwest_client(Some("curl/8.11.1"), Some(false)).await
                else {
                    return create_reqwest_client_error("Ipquery.io");
                };

                let Ok(result) = client_v4
                    .get("https://api.ipquery.io/?format=json")
                    .send()
                    .await
                else {
                    return request_error_ip_result(
                        "Ipquery.io",
                        "Unable to connect",
                    );
                };

                let Ok(json) = result.json::<serde_json::Value>().await else {
                    return parse_ip_error_ip_result("Ipquery.io", "Unable to parse json");
                };

                get_ipquery_io_info(json).await
            });

            let handle_v6 = tokio::spawn(async move {
                let Ok(client_v6) = create_reqwest_client(Some("curl/8.11.1"), Some(true)).await
                else {
                    return create_reqwest_client_error("Ipquery.io");
                };

                let Ok(result) = client_v6
                    .get("https://api.ipquery.io/?format=json")
                    .send()
                    .await
                else {
                    return request_error_ip_result(
                        "Ipquery.io",
                        "Unable to connect",
                    );
                };

                let Ok(json) = result.json::<serde_json::Value>().await else {
                    return parse_ip_error_ip_result("Ipquery.io", "Unable to parse json");
                };

                get_ipquery_io_info(json).await
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

async fn get_ipquery_io_info(json: serde_json::Value) -> IpResult {
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
        isp: Option<String>,
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

    let Ok(json_parsed) = serde_json::from_value::<IpQuery>(json) else {
        return parse_ip_error_ip_result("Ipquery.io", "Unable to parse json");
    };

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
        risk_tags.push(Proxy);
    }

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
            let isp = json_parsed.isp.isp;
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
            region: json_parsed.location.state,
            city: json_parsed.location.city,
            coordinates: {
                let latitude = json_parsed.location.latitude;
                let longitude = json_parsed.location.longitude;
                if let (Some(latitude), Some(longitude)) = (latitude, longitude) {
                    Some(Coordinates {
                        lat: latitude.to_string(),
                        lon: longitude.to_string(),
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
    }
}
