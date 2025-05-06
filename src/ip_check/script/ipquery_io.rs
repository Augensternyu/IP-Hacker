use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::RiskTag::{Hosting, Mobile, Proxy, Tor};
use crate::ip_check::ip_result::{
    AS, Coordinates, IpResult, Region, Risk, create_reqwest_client_error,
    json_parse_error_ip_result, parse_ip_error_ip_result, request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
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
                "Unable to parse ipquery.io",
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
                        "Unable to connect to ipquery.io",
                    );
                };

                let Ok(json) = result.json::<serde_json::Value>().await else {
                    return parse_ip_error_ip_result("Ipquery.io", "Unable to parse json");
                };

                get_ipquery_io_info(json).await
            });

            let handle_v6 = tokio::spawn(async move {
                let Ok(client_v4) = create_reqwest_client(Some("curl/8.11.1"), Some(true)).await
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
                        "Unable to connect to ipquery.io",
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
    let ip = if let Some(ip) = json.get("ip") {
        if let Some(ip) = ip.as_str() {
            ip.parse::<IpAddr>().ok()
        } else {
            return parse_ip_error_ip_result("Ipquery.io", "Unable to parse ip");
        }
    } else {
        return parse_ip_error_ip_result("Ipquery.io", "Unable to parse ip");
    };

    let Some(isp) = json.get("isp") else {
        return parse_ip_error_ip_result("Ipquery.io", "Unable to parse isp");
    };

    let asn = if let Some(asn) = isp.get("asn") {
        asn.as_str().map(|asn| {
            asn.to_string()
                .replace("AS", "")
                .parse::<u32>()
                .unwrap_or(0)
        })
    } else {
        None
    };

    let org = if let Some(org) = isp.get("org") {
        org.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    let location = if let Some(location) = json.get("location") {
        location
    } else {
        return parse_ip_error_ip_result("Ipquery.io", "Unable to parse location");
    };

    let country = if let Some(country) = location.get("country") {
        country.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    let region = if let Some(region) = location.get("state") {
        region.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    let city = if let Some(city) = location.get("city") {
        city.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    let lat = if let Some(lat) = location.get("latitude") {
        lat.as_f64().map(|lat| lat.to_string())
    } else {
        None
    };

    let lon = if let Some(long) = location.get("longitude") {
        long.as_f64().map(|long| long.to_string())
    } else {
        None
    };

    let timezone = if let Some(timezone) = location.get("timezone") {
        timezone.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    let risk = if let Some(risk) = json.get("risk") {
        risk
    } else {
        return parse_ip_error_ip_result("Ipquery.io", "Unable to parse risk");
    };

    let risk_score = if let Some(risk_score) = risk.get("risk_score") {
        risk_score.as_u64().map(|risk_score| risk_score as u16)
    } else {
        None
    };

    let mut risk_tags = vec![];

    if risk
        .get("is_mobile")
        .unwrap_or(&serde_json::Value::Bool(false))
        .as_bool()
        .unwrap_or(false)
    {
        risk_tags.push(Mobile);
    }

    if risk
        .get("is_vpn")
        .unwrap_or(&serde_json::Value::Bool(false))
        .as_bool()
        .unwrap_or(false)
    {
        risk_tags.push(Proxy);
    }

    if risk
        .get("is_tor")
        .unwrap_or(&serde_json::Value::Bool(false))
        .as_bool()
        .unwrap_or(false)
    {
        risk_tags.push(Tor);
    }

    if risk
        .get("is_datacenter")
        .unwrap_or(&serde_json::Value::Bool(false))
        .as_bool()
        .unwrap_or(false)
    {
        risk_tags.push(Hosting);
    }

    IpResult {
        success: true,
        error: No,
        provider: "Ipquery.io".to_string(),
        ip,
        autonomous_system: {
            if let (Some(asn), Some(org)) = (asn, org) {
                Some(AS {
                    number: asn,
                    name: org,
                })
            } else {
                None
            }
        },
        region: Some(Region {
            country,
            region,
            city,
            coordinates: {
                if let (Some(lat), Some(lon)) = (lat, lon) {
                    Some(Coordinates { lat, lon })
                } else {
                    None
                }
            },
            time_zone: timezone,
        }),
        risk: Some(Risk {
            risk: risk_score,
            tags: Some(risk_tags),
        }),
    }
}
