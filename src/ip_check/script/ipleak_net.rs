// src/ip_check/script/ipleak_net.rs

use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    AS, Coordinates, IpResult, Region, create_reqwest_client_error, json_parse_error_ip_result,
    request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct IpleakNet;

const PROVIDER_NAME: &str = "Ipleak.net";
const API_BASE_URL: &str = "https://ipleak.net/?mode=json&style=dns";

#[derive(Deserialize, Serialize, Debug)]
struct IpleakNetApiRespPayload {
    as_number: Option<u32>,
    isp_name: Option<String>,
    // country_code: Option<String>,
    country_name: Option<String>,
    // region_code: Option<String>,
    region_name: Option<String>,
    // continent_code: Option<String>,
    // continent_name: Option<String>,
    city_name: Option<String>,
    // postal_code: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    // accuracy_radius: Option<u32>,
    time_zone: Option<String>,
    // metro_code: Option<u32>,
    ip: String, // The IP address returned by the API for the query
                // query_text: String, // The original query text, could be IP or domain
                // query_type: String, // "ip" or "domain"
                // error fields are not explicitly defined, relying on HTTP status or lack of expected fields
}

fn sanitize_string_field(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim();
        // Ipleak.net seems to use null for empty/unknown rather than "-", but good to keep robust
        if trimmed.is_empty()
            || trimmed == "-"
            || trimmed == "未知"
            || trimmed.to_lowercase() == "unknown"
        {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[async_trait]
impl IpCheck for IpleakNet {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip_addr) = ip {
            // --- Query specific IP ---
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let client = match create_reqwest_client(None).await {
                    // Default client
                    Ok(c) => c,
                    Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                };

                let url = format!("{API_BASE_URL}&ip={ip_addr}");
                let response_result = client.get(&url).send().await;

                let mut result_without_time = match response_result {
                    Ok(r) => parse_ipleak_net_resp(r).await,
                    Err(e) => request_error_ip_result(PROVIDER_NAME, &e.to_string()),
                };
                result_without_time.used_time = Some(time_start.elapsed());
                result_without_time
            });

            match handle.await {
                Ok(result) => vec![result],
                Err(_) => vec![request_error_ip_result(
                    PROVIDER_NAME,
                    "Task for specific IP panicked or was cancelled.",
                )],
            }
        } else {
            // --- Query local IP (try IPv4 and IPv6) ---
            let mut results = Vec::new();

            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let client_v4 = match create_reqwest_client(Some(false)).await {
                    // Force IPv4
                    Ok(c) => c,
                    Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                };

                let response_result_v4 = client_v4.get(API_BASE_URL).send().await;
                let mut result_v4 = match response_result_v4 {
                    Ok(r) => parse_ipleak_net_resp(r).await,
                    Err(e) => {
                        request_error_ip_result(PROVIDER_NAME, &format!("IPv4 request failed: {e}"))
                    }
                };

                result_v4.used_time = Some(time_start.elapsed());
                result_v4
            });

            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let client_v6 = match create_reqwest_client(Some(true)).await {
                    // Force IPv6
                    Ok(c) => c,
                    Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                };

                let response_result_v6 = client_v6.get(API_BASE_URL).send().await;
                let mut result_v6 = match response_result_v6 {
                    Ok(r) => parse_ipleak_net_resp(r).await,
                    Err(e) => {
                        request_error_ip_result(PROVIDER_NAME, &format!("IPv6 request failed: {e}"))
                    }
                };
                result_v6.used_time = Some(time_start.elapsed());
                result_v6
            });

            if let Ok(r_v4) = handle_v4.await {
                results.push(r_v4);
            }
            if let Ok(r_v6) = handle_v6.await {
                let mut add_v6 = true;
                if let Some(existing_res_v4) = results.first() {
                    if existing_res_v4.success && r_v6.success && existing_res_v4.ip == r_v6.ip {
                        add_v6 = false;
                    }
                }
                if add_v6 {
                    results.push(r_v6);
                }
            }
            results
        }
    }
}

async fn parse_ipleak_net_resp(response: Response) -> IpResult {
    let status = response.status();

    if !status.is_success() {
        let err_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown HTTP error".to_string());
        let err_msg = format!(
            "HTTP Error {}: {}",
            status,
            err_text.chars().take(100).collect::<String>()
        );
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
    }

    let response_text = match response.text().await {
        Ok(text) => text,
        Err(e) => {
            return request_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to read response text (status was {status}): {e}"),
            );
        }
    };

    // Check for "Too many requests" or other plain text errors
    if response_text.to_lowercase().contains("too many requests") {
        return request_error_ip_result(PROVIDER_NAME, "API rate limit: Too many requests.");
    }
    // The API might return an empty response or non-JSON for certain errors
    if response_text.trim().is_empty() || !response_text.trim_start().starts_with('{') {
        return json_parse_error_ip_result(
            PROVIDER_NAME,
            &format!(
                "Response was not valid JSON. Snippet: '{}'",
                response_text.chars().take(100).collect::<String>()
            ),
        );
    }

    let payload: IpleakNetApiRespPayload = match serde_json::from_str(&response_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = response_text.chars().take(100).collect::<String>();
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse JSON: {e}. Response snippet: '{snippet}'"),
            );
        }
    };

    let parsed_ip = match payload.ip.parse::<IpAddr>() {
        Ok(ip_addr) => ip_addr,
        Err(_) => {
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse 'ip' from API: '{}'", payload.ip),
            );
        }
    };

    let country = sanitize_string_field(payload.country_name);
    let region_name = sanitize_string_field(payload.region_name);
    let city = sanitize_string_field(payload.city_name);
    let time_zone = sanitize_string_field(payload.time_zone.map(|tz| tz.replace("\\/", "/"))); // Fix escaped slashes

    let autonomous_system = match (payload.as_number, sanitize_string_field(payload.isp_name)) {
        (Some(number), Some(name)) => Some(AS { number, name }),
        (None, Some(name)) => Some(AS { number: 0, name }),
        (Some(number), None) => Some(AS {
            number,
            name: format!("AS{number}"),
        }), // Fallback name
        (None, None) => None,
    };

    let coordinates = match (payload.latitude, payload.longitude) {
        (Some(lat), Some(lon)) => Some(Coordinates {
            lat: lat.to_string(),
            lon: lon.to_string(),
        }),
        _ => None,
    };

    IpResult {
        success: true,
        error: No,
        provider: PROVIDER_NAME.to_string(),
        ip: Some(parsed_ip),
        autonomous_system,
        region: Some(Region {
            country,
            region: region_name,
            city,
            coordinates,
            time_zone,
        }),
        risk: None,      // API does not provide explicit risk information
        used_time: None, // Will be set by the caller
    }
}
