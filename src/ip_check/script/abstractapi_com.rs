// src/ip_check/script/abstractapi_com.rs

use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::RiskTag::{Hosting, Mobile, Proxy, Relay, Tor};
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

pub struct AbstractapiCom;

const PROVIDER_NAME: &str = "Abstractapi.com";
const API_KEY: &str = "508d5e4564b64e2eb2d2a077c9bcb429";
const API_BASE_URL: &str = "https://ip-intelligence.abstractapi.com/v1/";

// --- Serde Structs to match the API's nested JSON response ---

#[derive(Deserialize, Debug)]
struct TopLevelResp {
    ip_address: String,
    security: Option<ApiSecurity>,
    asn: Option<ApiAsn>,
    location: Option<ApiLocation>,
    timezone: Option<ApiTimezone>,
    error: Option<ApiError>, // To catch API-level errors
}

#[derive(Deserialize, Debug)]
struct ApiSecurity {
    is_vpn: Option<bool>,
    is_proxy: Option<bool>,
    is_tor: Option<bool>,
    is_hosting: Option<bool>,
    is_relay: Option<bool>,
    is_mobile: Option<bool>,
}

#[derive(Deserialize, Debug)]
struct ApiAsn {
    asn: Option<u32>,
    name: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ApiLocation {
    city: Option<String>,
    region: Option<String>,
    country: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
}

#[derive(Deserialize, Debug)]
struct ApiTimezone {
    name: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ApiError {
    message: String,
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
impl IpCheck for AbstractapiCom {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        let url = if let Some(ip_addr) = ip {
            format!("{API_BASE_URL}?api_key={API_KEY}&ip_address={ip_addr}")
        } else {
            format!("{API_BASE_URL}?api_key={API_KEY}")
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
                    Ok(r) => parse_abstractapi_com_resp(r).await,
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
                    Ok(r) => parse_abstractapi_com_resp(r).await,
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
                    Ok(r) => parse_abstractapi_com_resp(r).await,
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

async fn parse_abstractapi_com_resp(response: Response) -> IpResult {
    let status = response.status();
    let response_text = match response.text().await {
        Ok(text) => text,
        Err(e) => {
            return request_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to read response text (status was {status}): {e}"),
            );
        }
    };

    if !status.is_success() {
        return request_error_ip_result(
            PROVIDER_NAME,
            &format!("HTTP Error {status}: {response_text}"),
        );
    }

    let payload: TopLevelResp = match serde_json::from_str(&response_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = response_text.chars().take(100).collect::<String>();
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse JSON: {e}. Snippet: '{snippet}'"),
            );
        }
    };

    if let Some(error) = payload.error {
        return request_error_ip_result(PROVIDER_NAME, &error.message);
    }

    let parsed_ip = match payload.ip_address.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Could not parse IP from API: {}", payload.ip_address),
            );
        }
    };

    let autonomous_system = payload.asn.and_then(|asn_data| {
        match (asn_data.asn, sanitize_string_field(asn_data.name)) {
            (Some(number), Some(name)) => Some(AS { number, name }),
            (None, Some(name)) => Some(AS { number: 0, name }),
            _ => None,
        }
    });

    let (country, region, city, coordinates) = if let Some(loc) = payload.location {
        (
            sanitize_string_field(loc.country),
            sanitize_string_field(loc.region),
            sanitize_string_field(loc.city),
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

    let time_zone = payload
        .timezone
        .and_then(|tz| sanitize_string_field(tz.name));

    let risk = payload.security.map(|sec| {
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
        if sec.is_hosting == Some(true) {
            tags_set.insert(Hosting);
        }
        if sec.is_relay == Some(true) {
            tags_set.insert(Relay);
        }
        if sec.is_mobile == Some(true) {
            tags_set.insert(Mobile);
        }
        let tags_vec: Vec<_> = tags_set.into_iter().collect();
        Risk {
            risk: None, // API does not provide a numeric risk score
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
