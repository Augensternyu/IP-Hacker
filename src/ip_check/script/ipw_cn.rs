// src/ip_check/script/ipw_cn.rs

use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::{self, No};
use crate::ip_check::ip_result::{
    AS, Coordinates, IpResult, Region, create_reqwest_client_error,
    json_parse_error_ip_result, not_support_error, request_error_ip_result, parse_ip_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv6Addr};

pub struct IpwCn;

const PROVIDER_NAME: &str = "Ipw.cn";

#[derive(Deserialize, Serialize, Debug)]
struct IpwCnMyIpResp {
    #[serde(rename = "result")]
    _result: bool, // Not directly used, success is implied by parsing
    #[serde(rename = "IP")]
    ip: Option<String>,
    #[serde(rename = "IPVersion")]
    ip_version: Option<String>,
    // message: Option<String>,
    // code: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
struct IpwCnApiDataPayload {
    continent: Option<String>,
    country: Option<String>,
    // zipcode: Option<String>,
    timezone: Option<String>,
    // accuracy: Option<String>,
    // owner: Option<String>, // Often redundant with ISP or less specific
    isp: Option<String>,
    // source: Option<String>,
    // areacode: Option<String>,
    // adcode: Option<String>,
    asnumber: Option<String>, // String "9808"
    lat: Option<String>,
    lng: Option<String>,
    // radius: Option<String>,
    prov: Option<String>,
    city: Option<String>,
    district: Option<String>,
    // currency_code: Option<String>,
    // currency_name: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
struct IpwCnApiRespPayload {
    code: String, // "Success" or other error codes
    data: Option<IpwCnApiDataPayload>,
    // charge: bool,
    msg: Option<String>,
    ip: Option<String>, // The IP that was queried
    // coordsys: Option<String>,
}


async fn fetch_and_parse_ip_details(client: &reqwest::Client, target_ip: Ipv6Addr) -> IpResult {
    let url = format!(
        "https://rest.ipw.cn/api/aw/v1/ipv6?ip={target_ip}&warning=please-direct-use-please-use-ipplus360.com"
    );

    let response = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => return request_error_ip_result(PROVIDER_NAME, &format!("Failed to connect to details API: {e}")),
    };

    if !response.status().is_success() {
        return request_error_ip_result(PROVIDER_NAME, &format!("Details API HTTP Error: {}", response.status()));
    }

    let response_text = match response.text().await {
        Ok(text) => text,
        Err(e) => {
            return request_error_ip_result(PROVIDER_NAME, &format!("Failed to read details response text: {e}"));
        }
    };

    let payload: IpwCnApiRespPayload = match serde_json::from_str(&response_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = response_text.chars().take(100).collect::<String>();
            return json_parse_error_ip_result(PROVIDER_NAME, &format!("Failed to parse details JSON: {e}. Response snippet: '{snippet}'"));
        }
    };

    if payload.code.to_lowercase() != "success" {
        let err_msg = payload.msg.unwrap_or_else(|| format!("API error code: {}", payload.code));
        let mut err_res = request_error_ip_result(PROVIDER_NAME, &err_msg);
        // Try to include the IP address if returned by API, even on error
        if let Some(ip_str) = payload.ip.as_deref() {
            err_res.ip = ip_str.parse::<IpAddr>().ok();
        }
        return err_res;
    }

    let data = match payload.data {
        Some(d) => d,
        None => return json_parse_error_ip_result(PROVIDER_NAME, "Details API success but 'data' field is missing."),
    };

    // Ensure the IP in the response matches the one we queried, or is parseable
    let final_ip_addr = match payload.ip.as_deref().map(str::parse::<IpAddr>) {
        Some(Ok(ip)) => ip,
        _ => IpAddr::V6(target_ip), // Fallback to the IP we intended to query
    };

    // It's an IPv6 only API, so if the final_ip_addr is not V6, something is very wrong.
    if !final_ip_addr.is_ipv6() {
        return parse_ip_error_ip_result(PROVIDER_NAME, "Details API returned a non-IPv6 address for an IPv6 query.");
    }

    let as_number = data.asnumber.and_then(|s| s.parse::<u32>().ok());

    IpResult {
        success: true,
        error: No,
        provider: PROVIDER_NAME.to_string(),
        ip: Some(final_ip_addr),
        autonomous_system: match (as_number, data.isp) {
            (Some(num), Some(name)) => Some(AS { number: num, name }),
            (None, Some(name)) => Some(AS { number: 0, name }), // ISP name without ASN
            _ => None,
        },
        region: Some(Region {
            country: data.country,
            region: data.prov,
            city: data.city.or(data.district), // Prefer city, fallback to district
            coordinates: match (data.lat, data.lng) {
                (Some(lat_str), Some(lon_str)) => Some(Coordinates { lat: lat_str, lon: lon_str }),
                _ => None,
            },
            time_zone: data.timezone,
        }),
        risk: None, // API does not provide direct risk flags
        used_time: None, // To be set by caller
    }
}


#[async_trait]
impl IpCheck for IpwCn {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        let target_ipv6_opt: Option<Ipv6Addr> = match ip {
            Some(IpAddr::V6(ipv6_addr)) => Some(ipv6_addr),
            Some(IpAddr::V4(_)) => {
                // API only supports IPv6 for details
                return vec![not_support_error(PROVIDER_NAME)];
            }
            None => { // Need to fetch local IPv6
                let client_for_myip = match create_reqwest_client(Some(true)).await { // Must use IPv6 client
                    Ok(c) => c,
                    Err(_) => return vec![create_reqwest_client_error(PROVIDER_NAME)],
                };
                match client_for_myip.get("https://6.ipw.cn/api/ip/myip?json").send().await {
                    Ok(resp) => {
                        if !resp.status().is_success() {
                            return vec![request_error_ip_result(PROVIDER_NAME, &format!("myip API HTTP Error: {}", resp.status()))];
                        }
                        match resp.json::<IpwCnMyIpResp>().await {
                            Ok(my_ip_payload) => {
                                if my_ip_payload.ip_version.as_deref() == Some("IPv6") {
                                    my_ip_payload.ip.and_then(|s| s.parse::<Ipv6Addr>().ok())
                                } else {
                                    None // Not an IPv6 address or version mismatch
                                }
                            }
                            Err(e) => {
                                return vec![json_parse_error_ip_result(PROVIDER_NAME, &format!("Failed to parse myip JSON: {e}"))];
                            }
                        }
                    }
                    Err(e) => {
                        return vec![request_error_ip_result(PROVIDER_NAME, &format!("Failed to connect to myip API: {e}"))];
                    }
                }
            }
        };

        let target_ipv6 = if let Some(ipv6) = target_ipv6_opt { ipv6 } else {
            // If 'ip' was None and we couldn't get a local IPv6, then we can't proceed
            let mut res = not_support_error(PROVIDER_NAME);
            res.error = IpCheckError::Request("Could not determine a local IPv6 address to query.".to_string());
            return vec![res];
        };

        // Now use the determined target_ipv6 to query details
        let handle = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            // Use a default client for the details API as per problem description ("请求使用ipv6与否默认即可")
            // However, since the API itself is IPv6-specific (rest.ipw.cn/api/aw/v1/ipv6),
            // a client that can make IPv6 requests might be implicitly needed if the host has IPv6.
            // Using `None` for create_reqwest_client is "default".
            let client_for_details = match create_reqwest_client(None).await {
                Ok(c) => c,
                Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
            };

            let mut result_without_time = fetch_and_parse_ip_details(client_for_details, target_ipv6).await;
            result_without_time.used_time = Some(time_start.elapsed());
            result_without_time
        });

        match handle.await {
            Ok(result) => vec![result],
            Err(_) => vec![request_error_ip_result(PROVIDER_NAME, "Task panicked or was cancelled.")],
        }
    }
}