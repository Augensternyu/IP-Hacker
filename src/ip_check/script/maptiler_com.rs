// src/ip_check/script/maptiler_com.rs

use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, not_support_error, request_error_ip_result, Coordinates,
    IpResult, Region,
};
use crate::ip_check::script::create_reqwest_client;
use crate::ip_check::IpCheck;
use async_trait::async_trait;
use reqwest::Response;
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr};

pub struct MaptilerCom;

const PROVIDER_NAME: &str = "Maptiler.com";
const API_KEY: &str = "jEQqObznLQvsLCBdYQ2W";
const API_URL: &str = "https://api.maptiler.com/geolocation/ip.json";

#[derive(Deserialize, Debug)]
struct MaptilerApiRespPayload {
    country: Option<String>,
    city: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    region: Option<String>,
    timezone: Option<String>,
    message: Option<String>,
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
impl IpCheck for MaptilerCom {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            return vec![not_support_error(PROVIDER_NAME)];
        }

        let mut results = Vec::new();
        let url = format!("{API_URL}?key={API_KEY}");

        let handle_v4 = tokio::spawn({
            let url = url.clone();
            async move {
                let time_start = tokio::time::Instant::now();
                let client_v4 = match create_reqwest_client(Some(false)).await {
                    Ok(c) => c,
                    Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                };

                let response_result = client_v4.get(&url).send().await;
                let mut result = match response_result {
                    Ok(r) => parse_maptiler_com_resp(r, false).await, // is_ipv6 = false
                    Err(e) => request_error_ip_result(PROVIDER_NAME, &e.to_string()),
                };
                result.used_time = Some(time_start.elapsed());
                result
            }
        });

        let handle_v6 = tokio::spawn({
            let url = url.clone();
            async move {
                let time_start = tokio::time::Instant::now();
                let client_v6 = match create_reqwest_client(Some(true)).await {
                    Ok(c) => c,
                    Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                };

                let response_result = client_v6.get(&url).send().await;
                let mut result = match response_result {
                    Ok(r) => parse_maptiler_com_resp(r, true).await, // is_ipv6 = true
                    Err(e) => request_error_ip_result(PROVIDER_NAME, &e.to_string()),
                };
                result.used_time = Some(time_start.elapsed());
                result
            }
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

async fn parse_maptiler_com_resp(response: Response, is_ipv6_request: bool) -> IpResult {
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

    let payload: MaptilerApiRespPayload = match serde_json::from_str(&response_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = response_text.chars().take(100).collect::<String>();
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse JSON: {e}. Snippet: '{snippet}'"),
            );
        }
    };

    if let Some(message) = payload.message {
        return request_error_ip_result(PROVIDER_NAME, &message);
    }

    // **FIXED LOGIC**: Since the API doesn't return an IP, we construct a placeholder.
    // If it was an IPv6 request, we assume success is for an IPv6 address (which we don't know).
    // If it was an IPv4 request, we know the IP is an IPv4 one.
    // For simplicity and to avoid ambiguity without the real IP, we'll use a specific placeholder.
    let placeholder_ip = if is_ipv6_request {
        // If we want to show a specific IPv6 placeholder, we could use ::, but that can be confusing.
        // Let's return None for IPv6 success since we can't know the IP. The table logic handles None.
        // Or, more clearly, let's just use the `is_bogon` address to indicate it's a placeholder.
        // A better approach is to return a specific error or a result without an IP.
        // Let's stick to the request: set to 0.0.0.0. It's technically wrong for an IPv6 request,
        // but it fulfills the request to show *something* and avoid the parse error.
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
    } else {
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
    };

    let country = sanitize_string_field(payload.country);
    let region = sanitize_string_field(payload.region);
    let city = sanitize_string_field(payload.city);
    let time_zone = sanitize_string_field(payload.timezone);

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
        ip: Some(placeholder_ip), // Using the placeholder
        autonomous_system: None,
        region: Some(Region {
            country,
            region,
            city,
            coordinates,
            time_zone,
        }),
        risk: None,
        used_time: None,
    }
}
