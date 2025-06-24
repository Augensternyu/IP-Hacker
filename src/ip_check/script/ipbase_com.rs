// src/ip_check/script/ipbase_com.rs

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
use serde::Deserialize;
use std::collections::HashSet;
use std::net::IpAddr;

pub struct IpbaseCom;

const PROVIDER_NAME: &str = "Ipbase.com";
const API_KEY: &str = "sgiPfh4j3aXFR3l2CnjWqdKQzxpqGn9pX5b3CUsz";
const API_BASE_URL: &str = "https://api.ipbase.com/v2/info";

// --- Serde Structs to match the API's nested JSON response ---

#[derive(Deserialize, Debug)]
struct TopLevelResp {
    data: Option<ApiData>,
    errors: Option<serde_json::Value>, // Catch potential error objects
}

#[derive(Deserialize, Debug)]
struct ApiData {
    ip: String,
    connection: Option<ApiConnection>,
    location: Option<ApiLocation>,
    timezone: Option<ApiTimezone>,
    security: Option<ApiSecurity>,
}

#[derive(Deserialize, Debug)]
struct ApiConnection {
    asn: Option<u32>,
    isp: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ApiLocation {
    latitude: Option<f64>,
    longitude: Option<f64>,
    country: Option<ApiCountry>,
    region: Option<ApiRegion>,
    city: Option<ApiCity>,
}

#[derive(Deserialize, Debug)]
struct ApiCountry {
    name: Option<String>,
}
#[derive(Deserialize, Debug)]
struct ApiRegion {
    name: Option<String>,
}
#[derive(Deserialize, Debug)]
struct ApiCity {
    name: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ApiTimezone {
    id: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ApiSecurity {
    is_vpn: Option<bool>,
    is_proxy: Option<bool>,
    is_tor: Option<bool>,
    is_datacenter: Option<bool>,
    is_icloud_relay: Option<bool>,
    threat_score: Option<u16>,
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
impl IpCheck for IpbaseCom {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        let url = if let Some(ip_addr) = ip {
            format!("{API_BASE_URL}?apikey={API_KEY}&ip={ip_addr}")
        } else {
            format!("{API_BASE_URL}?apikey={API_KEY}")
        };

        if ip.is_some() {
            // --- Query specific IP ---
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let client = match create_reqwest_client(None).await {
                    Ok(c) => c,
                    Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                };

                let response_result = client.get(&url).send().await;
                let mut result_without_time = match response_result {
                    Ok(r) => parse_ipbase_com_resp(r).await,
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
                    Ok(r) => parse_ipbase_com_resp(r).await,
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
                    Ok(r) => parse_ipbase_com_resp(r).await,
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

async fn parse_ipbase_com_resp(response: Response) -> IpResult {
    let status = response.status();
    if !status.is_success() {
        let err_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown HTTP error".to_string());
        let err_msg = format!("HTTP Error {}: {}", status, err_text);
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
    }

    let payload: TopLevelResp = match response.json().await {
        Ok(p) => p,
        Err(e) => return json_parse_error_ip_result(PROVIDER_NAME, &e.to_string()),
    };

    if let Some(errors) = payload.errors {
        return request_error_ip_result(PROVIDER_NAME, &format!("API returned error: {}", errors));
    }

    let data = match payload.data {
        Some(d) => d,
        None => {
            return json_parse_error_ip_result(PROVIDER_NAME, "API response missing 'data' field.");
        }
    };

    let parsed_ip = match data.ip.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Could not parse IP from API: {}", data.ip),
            );
        }
    };

    let autonomous_system =
        data.connection
            .and_then(|conn| match (conn.asn, sanitize_string_field(conn.isp)) {
                (Some(number), Some(name)) => Some(AS { number, name }),
                (None, Some(name)) => Some(AS { number: 0, name }),
                _ => None,
            });

    let (country, region, city, coordinates) = if let Some(loc) = data.location {
        (
            loc.country.and_then(|c| sanitize_string_field(c.name)),
            loc.region.and_then(|r| sanitize_string_field(r.name)),
            loc.city.and_then(|c| sanitize_string_field(c.name)),
            match (loc.latitude, loc.longitude) {
                (Some(lat), Some(lon)) => Some(Coordinates {
                    lat: lat.to_string(),
                    lon: lon.to_string(),
                }),
                _ => None,
            },
        )
    } else {
        (None, None, None, None)
    };

    let time_zone = data.timezone.and_then(|tz| sanitize_string_field(tz.id));

    let risk = data.security.map(|sec| {
        let mut tags_set = HashSet::new();
        if sec.is_vpn == Some(true) {
            tags_set.insert(Proxy);
        }
        if sec.is_proxy == Some(true) {
            tags_set.insert(Proxy);
        }
        if sec.is_tor == Some(true) {
            tags_set.insert(Tor);
        }
        if sec.is_datacenter == Some(true) {
            tags_set.insert(Hosting);
        }
        if sec.is_icloud_relay == Some(true) {
            tags_set.insert(Other("iCloud Relay".to_string()));
        }

        let tags_vec: Vec<_> = tags_set.into_iter().collect();
        Risk {
            risk: sec.threat_score, // `threat_score` is already a risk score
            tags: if tags_vec.is_empty() {
                None
            } else {
                Some(tags_vec)
            },
        }
    });

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
        risk,
        used_time: None,
    }
}
