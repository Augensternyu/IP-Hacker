use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::{
    AS, Coordinates, IpCheckError, IpResult, Region, create_reqwest_client_error,
    json_parse_error_ip_result, parse_ip_error_ip_result, request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use regex::Regex;
use serde_json::Value;
use std::net::IpAddr;
use std::str::FromStr;

pub struct IpInfoIo;

#[async_trait]
impl IpCheck for IpInfoIo {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            let time_start = tokio::time::Instant::now();
            let Ok(client_v4) = create_reqwest_client(Some("curl/8.11.1"), Some(false)).await
            else {
                return vec![create_reqwest_client_error("Ipinfo.io")];
            };

            let res = if let Ok(res) = client_v4
                .get(format!("https://ipinfo.io/{ip}"))
                .send()
                .await
            {
                res
            } else {
                return vec![request_error_ip_result("Ipinfo.io", "Unable to connect")];
            };

            if res.status() == 200 {
                let json = if let Ok(json) = res.json::<Value>().await {
                    json
                } else {
                    return vec![parse_ip_error_ip_result(
                        "Ipinfo.io",
                        "Unable to parse json",
                    )];
                };

                vec![{
                    let mut result_without_time = get_ipinfo_io(json).await;
                    let end_time = time_start.elapsed();
                    result_without_time.used_time = Some(end_time);
                    result_without_time
                }]
            } else {
                vec![request_error_ip_result(
                    "Ipinfo.io",
                    "Server returned an error",
                )]
            }
        } else {
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v4) = create_reqwest_client(Some("curl/8.11.1"), Some(false)).await
                else {
                    return create_reqwest_client_error("Ipinfo.io");
                };

                let Ok(result) = client_v4.get("https://ipinfo.io").send().await else {
                    return request_error_ip_result("Ipinfo.io", "Unable to connect");
                };

                if result.status() == 200 {
                    let json = if let Ok(json) = result.json::<Value>().await {
                        json
                    } else {
                        return parse_ip_error_ip_result("Ipinfo.io", "Unable to parse json");
                    };
                    let mut result_without_time = get_ipinfo_io(json).await;
                    let end_time = time_start.elapsed();
                    result_without_time.used_time = Some(end_time);
                    result_without_time
                } else {
                    request_error_ip_result("Ipinfo.io", "ipinfo.io returned an error")
                }
            });

            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v6) = create_reqwest_client(Some("curl/8.11.1"), Some(true)).await
                else {
                    return create_reqwest_client_error("Ipinfo.io");
                };

                let Ok(result) = client_v6.get("https://v6.ipinfo.io").send().await else {
                    return request_error_ip_result("Ipinfo.io", "Unable to connect");
                };

                if result.status() == 200 {
                    let json = if let Ok(json) = result.json::<Value>().await {
                        json
                    } else {
                        return parse_ip_error_ip_result("Ipinfo.io", "Unable to parse json");
                    };
                    let mut result_without_time = get_ipinfo_io(json).await;
                    let end_time = time_start.elapsed();
                    result_without_time.used_time = Some(end_time);
                    result_without_time
                } else {
                    request_error_ip_result("Ipinfo.io", "ipinfo.io returned an error")
                }
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

async fn get_ipinfo_io(ip: Value) -> IpResult {
    let country = if let Some(country) = ip.get("country") {
        country.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    let region = if let Some(region) = ip.get("region") {
        region.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    let city = if let Some(city) = ip.get("city") {
        city.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    let org_str = if let Some(org) = ip.get("org") {
        org.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    let re = Regex::new(r"^(AS\d+)\s+(.*)$").unwrap();
    let Some((asn, org)) = (if org_str.is_some() {
        let org_str = org_str.unwrap();
        let caps = re.captures(&org_str);
        if let Some(caps) = caps {
            let asn = caps.get(1).unwrap().as_str().to_string();
            let org = caps.get(2).unwrap().as_str().to_string();
            Some((asn, org))
        } else {
            None
        }
    } else {
        None
    }) else {
        return json_parse_error_ip_result("Ipinfo.io", "Unable to parse json");
    };

    let asn = asn.replace("AS", "").parse::<u32>().unwrap_or(0);

    let loc = if let Some(loc) = ip.get("loc") {
        loc.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    let temp = loc.unwrap_or(String::new());
    let (lat, lon) = temp.split_once(',').unwrap();

    let time_zone = if let Some(time_zone) = ip.get("timezone") {
        time_zone.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    IpResult {
        success: true,
        error: IpCheckError::No,
        provider: "Ipinfo.io".to_string(),
        ip: Some(IpAddr::from_str(ip["ip"].as_str().unwrap()).unwrap()),
        autonomous_system: Some(AS {
            number: asn,
            name: org,
        }),
        region: Some(Region {
            country,
            region,
            city,
            coordinates: Some(Coordinates {
                lat: lat.to_string(),
                lon: lon.to_string(),
            }),
            time_zone,
        }),
        risk: None,
        used_time: None,
    }
}
