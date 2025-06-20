use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    AS, Coordinates, IpResult, Region, create_reqwest_client_error, json_parse_error_ip_result,
    parse_ip_error_ip_result, request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use reqwest::{Response, header};
use std::net::IpAddr;
use std::str::FromStr;

pub struct IpSb;

#[async_trait]
impl IpCheck for IpSb {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            let handle = tokio::spawn(async move {
                let Ok(client_v4) = create_reqwest_client(None, None).await else {
                    return create_reqwest_client_error("IP.sb");
                };

                let Ok(result) = client_v4
                    .get(format!("https://api.ip.sb/geoip/{ip}"))
                    .headers(headers())
                    .send()
                    .await
                else {
                    return request_error_ip_result("IP.sb", "Unable to connect");
                };

                get_ip_sb_info(result).await
            });

            let mut results = Vec::new();
            if let Ok(result) = handle.await {
                results.push(result);
            }
            results
        } else {
            let handle_v4 = tokio::spawn(async move {
                let Ok(client_v4) = create_reqwest_client(None, Some(false)).await else {
                    return create_reqwest_client_error("IP.sb");
                };

                let Ok(result) = client_v4
                    .get("https://api.ip.sb/geoip/")
                    .headers(headers())
                    .send()
                    .await
                else {
                    return request_error_ip_result("IP.sb", "Unable to connect");
                };

                get_ip_sb_info(result).await
            });

            let handle_v6 = tokio::spawn(async move {
                let Ok(client_v6) = create_reqwest_client(None, Some(true)).await else {
                    return create_reqwest_client_error("IP.sb");
                };

                let Ok(result) = client_v6
                    .get("https://api.ip.sb/geoip/")
                    .headers(headers())
                    .send()
                    .await
                else {
                    return request_error_ip_result("IP.sb", "Unable to connect");
                };

                get_ip_sb_info(result).await
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

async fn get_ip_sb_info(response: Response) -> IpResult {
    if !response.status().is_success() {
        return request_error_ip_result("IP.sb", "Unable to connect");
    }

    let Ok(json) = response.json::<serde_json::Value>().await else {
        return request_error_ip_result("IP.sb", "Unable to parse the returned result into Json");
    };

    let ip = if let Some(ip) = json.get("ip") {
        if let Some(ip) = ip.as_str() {
            match IpAddr::from_str(ip) {
                Ok(ip) => ip,
                Err(_) => {
                    return parse_ip_error_ip_result(
                        "IP.sb",
                        "Unable to parse the returned result into Json",
                    );
                }
            }
        } else {
            return json_parse_error_ip_result("IP.sb", "Unable to get value for `ip`");
        }
    } else {
        return json_parse_error_ip_result("IP.sb", "Unable to get value for `ip`");
    };

    let country = if let Some(country) = json.get("country") {
        country.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    let region = if let Some(region) = json.get("region") {
        region.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    let city = if let Some(city) = json.get("city") {
        city.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    let asn = if let Some(asn) = json.get("asn") {
        asn.as_u64()
    } else {
        None
    };

    let org = if let Some(org) = json.get("asn_organization") {
        org.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    let lat = if let Some(lat) = json.get("latitude") {
        lat.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    let lon = if let Some(lon) = json.get("longitude") {
        lon.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    let timezone = if let Some(timezone) = json.get("timezone") {
        timezone.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    IpResult {
        success: true,
        error: No,
        provider: "IP.sb".to_string(),
        ip: Some(ip),
        autonomous_system: {
            if let (Some(asn), Some(org)) = (asn, org) {
                Some(AS {
                    number: u32::try_from(asn).unwrap_or(0),
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
        risk: None,
    }
}

fn headers() -> reqwest::header::HeaderMap {
    let mut headers = header::HeaderMap::new();
    headers.insert("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".parse().unwrap());
    headers.insert("accept-language", "zh-CN,zh;q=0.9".parse().unwrap());
    headers.insert("cache-control", "max-age=0".parse().unwrap());
    headers.insert("dnt", "1".parse().unwrap());
    headers.insert("priority", "u=0, i".parse().unwrap());
    headers.insert(
        "sec-ch-ua",
        "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\""
            .parse()
            .unwrap(),
    );
    headers.insert("sec-ch-ua-mobile", "?0".parse().unwrap());
    headers.insert("sec-ch-ua-platform", "\"Linux\"".parse().unwrap());
    headers.insert("sec-fetch-dest", "document".parse().unwrap());
    headers.insert("sec-fetch-mode", "navigate".parse().unwrap());
    headers.insert("sec-fetch-site", "none".parse().unwrap());
    headers.insert("sec-fetch-user", "?1".parse().unwrap());
    headers.insert("upgrade-insecure-requests", "1".parse().unwrap());
    headers.insert("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".parse().unwrap());

    headers
}
