// src/ip_check/script/ipapi_is.rs

use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::RiskTag::{Hosting, Mobile, Proxy, Tor};
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, request_error_ip_result, Coordinates, IpResult, Region,
    Risk, AS,
};
use crate::ip_check::script::create_reqwest_client;
use crate::ip_check::IpCheck;
use async_trait::async_trait;
use reqwest::Response;
use serde::Deserialize;
use std::collections::HashSet;
use std::net::IpAddr;

pub struct IpapiIs;

const PROVIDER_NAME: &str = "Ipapi.is";
const API_BASE_URL: &str = "https://api.ipapi.is/";

// --- Serde Structs to match the API's nested JSON response ---

#[derive(Deserialize, Debug)]
struct TopLevelResp {
    ip: String,
    is_mobile: Option<bool>,
    is_datacenter: Option<bool>,
    is_tor: Option<bool>,
    is_proxy: Option<bool>,
    is_vpn: Option<bool>,
    company: Option<ApiCompany>,
    asn: Option<ApiAsn>,
    location: Option<ApiLocation>,
    // Error field is not standard, we check response status
}

#[derive(Deserialize, Debug)]
struct ApiCompany {
    name: Option<String>,
    // Other fields are not used for IpResult
}

#[derive(Deserialize, Debug)]
struct ApiAsn {
    asn: Option<u32>,
    org: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ApiLocation {
    country: Option<String>,
    state: Option<String>,
    city: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    timezone: Option<String>,
}

fn sanitize_string_field(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[async_trait]
impl IpCheck for IpapiIs {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        let url = if let Some(ip_addr) = ip {
            format!("{API_BASE_URL}?q={ip_addr}")
        } else {
            API_BASE_URL.to_string()
        };

        if ip.is_some() {
            // --- Query specific IP ---
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // API can be accessed via IPv4 or IPv6, client choice is default
                let client = match create_reqwest_client(None).await {
                    Ok(c) => c,
                    Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                };

                let response_result = client.get(&url).send().await;
                let mut result_without_time = match response_result {
                    Ok(r) => parse_ipapi_is_resp(r).await,
                    Err(e) => request_error_ip_result(PROVIDER_NAME, &e.to_string()),
                };
                result_without_time.used_time = Some(time_start.elapsed());
                result_without_time
            });
            vec![handle.await.unwrap_or_else(|_| {
                request_error_ip_result(PROVIDER_NAME, "Task panicked or was cancelled.")
            })]
        } else {
            // --- Query local IP (v4 and v6) ---
            let mut results = Vec::new();
            let url_v4 = url.clone();
            let url_v6 = url;

            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let client_v4 = match create_reqwest_client(Some(false)).await {
                    Ok(c) => c,
                    Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                };

                let response_result_v4 = client_v4.get(&url_v4).send().await;
                let mut result_v4 = match response_result_v4 {
                    Ok(r) => parse_ipapi_is_resp(r).await,
                    Err(e) => request_error_ip_result(PROVIDER_NAME, &format!("IPv4 request: {e}")),
                };
                result_v4.used_time = Some(time_start.elapsed());
                result_v4
            });

            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let client_v6 = match create_reqwest_client(Some(true)).await {
                    Ok(c) => c,
                    Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                };
                let response_result_v6 = client_v6.get(&url_v6).send().await;
                let mut result_v6 = match response_result_v6 {
                    Ok(r) => parse_ipapi_is_resp(r).await,
                    Err(e) => request_error_ip_result(PROVIDER_NAME, &format!("IPv6 request: {e}")),
                };
                result_v6.used_time = Some(time_start.elapsed());
                result_v6
            });

            if let Ok(r) = handle_v4.await {
                results.push(r);
            }
            if let Ok(r) = handle_v6.await {
                if !results.iter().any(|res| res.success && res.ip == r.ip) {
                    results.push(r);
                }
            }
            results
        }
    }
}

async fn parse_ipapi_is_resp(response: Response) -> IpResult {
    let status = response.status();
    if !status.is_success() {
        let err_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown HTTP error".to_string());
        let err_msg = format!("HTTP Error {status}: {err_text}");
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
    }

    let payload: TopLevelResp = match response.json().await {
        Ok(p) => p,
        Err(e) => return json_parse_error_ip_result(PROVIDER_NAME, &e.to_string()),
    };

    let parsed_ip = match payload.ip.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Could not parse IP from API: {}", payload.ip),
            );
        }
    };

    let autonomous_system = match payload.asn {
        Some(asn_data) => {
            // Prioritize the 'org' field from ASN, fallback to company name
            let name = sanitize_string_field(asn_data.org)
                .or_else(|| payload.company.and_then(|c| sanitize_string_field(c.name)));

            match (asn_data.asn, name) {
                (Some(number), Some(name)) => Some(AS { number, name }),
                (None, Some(name)) => Some(AS { number: 0, name }),
                _ => None,
            }
        }
        None => None,
    };

    let (country, region, city, coordinates, time_zone) = if let Some(loc) = payload.location {
        (
            sanitize_string_field(loc.country),
            sanitize_string_field(loc.state),
            sanitize_string_field(loc.city),
            match (loc.latitude, loc.longitude) {
                (Some(lat), Some(lon)) => Some(Coordinates {
                    lat: lat.to_string(),
                    lon: lon.to_string(),
                }),
                _ => None,
            },
            sanitize_string_field(loc.timezone),
        )
    } else {
        (None, None, None, None, None)
    };

    let mut tags_set = HashSet::new();
    if payload.is_mobile == Some(true) {
        tags_set.insert(Mobile);
    }
    if payload.is_datacenter == Some(true) {
        tags_set.insert(Hosting);
    }
    if payload.is_tor == Some(true) {
        tags_set.insert(Tor);
    }
    if payload.is_proxy == Some(true) {
        tags_set.insert(Proxy);
    }
    if payload.is_vpn == Some(true) {
        tags_set.insert(Proxy);
    }

    let tags_vec: Vec<_> = tags_set.into_iter().collect();

    IpResult {
        success: true,
        error: No,
        provider: PROVIDER_NAME.to_string(),
        ip: Some(parsed_ip),
        autonomous_system,
        region: Some(Region {
            country,
            region,
            city,
            coordinates,
            time_zone,
        }),
        risk: Some(Risk {
            risk: None, // API provides abuser_score, but we're not using it as a direct risk score for now.
            tags: if tags_vec.is_empty() {
                None
            } else {
                Some(tags_vec)
            },
        }),
        used_time: None,
    }
}
