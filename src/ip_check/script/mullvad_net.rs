// src/ip_check/script/mullvad_net.rs

use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::RiskTag;
use crate::ip_check::ip_result::{
    AS, Coordinates, IpResult, Region, Risk, create_reqwest_client_error,
    json_parse_error_ip_result, not_support_error, request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use reqwest::Response;
use serde::Deserialize;
use std::net::IpAddr;

pub struct MullvadNet;

const PROVIDER_NAME: &str = "Mullvad.net";
const API_URL: &str = "https://am.i.mullvad.net/json";

// --- Serde Structs to match the API's JSON response ---

#[derive(Deserialize, Debug)]
struct BlacklistedInfo {
    blacklisted: bool,
}

#[derive(Deserialize, Debug)]
struct MullvadApiRespPayload {
    ip: String,
    country: Option<String>,
    city: Option<String>,
    longitude: Option<f64>,
    latitude: Option<f64>,
    mullvad_exit_ip: Option<bool>,
    blacklisted: Option<BlacklistedInfo>,
    organization: Option<String>,
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
impl IpCheck for MullvadNet {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            // This API only supports checking the local IP.
            return vec![not_support_error(PROVIDER_NAME)];
        }

        // --- Query local IP (only IPv4 is supported by the API) ---
        let handle_v4 = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            let client_v4 = match create_reqwest_client(None).await {
                // Force IPv4 as per prompt
                Ok(c) => c,
                Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
            };

            let response_result = client_v4.get(API_URL).send().await;
            let mut result = match response_result {
                Ok(r) => parse_mullvad_net_resp(r).await,
                Err(e) => request_error_ip_result(PROVIDER_NAME, &e.to_string()),
            };
            result.used_time = Some(time_start.elapsed());
            result
        });

        match handle_v4.await {
            Ok(result) => vec![result],
            Err(_) => vec![request_error_ip_result(
                PROVIDER_NAME,
                "Task panicked or was cancelled.",
            )],
        }
    }
}

async fn parse_mullvad_net_resp(response: Response) -> IpResult {
    let status = response.status();
    if !status.is_success() {
        let err_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown HTTP error".to_string());
        return request_error_ip_result(PROVIDER_NAME, &format!("HTTP Error {status}: {err_text}"));
    }

    let response_text = match response.text().await {
        Ok(text) => text,
        Err(e) => {
            return request_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to read response text: {e}"),
            );
        }
    };

    let payload: MullvadApiRespPayload = match serde_json::from_str(&response_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = response_text.chars().take(100).collect::<String>();
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse JSON: {e}. Snippet: '{snippet}'"),
            );
        }
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

    let autonomous_system = sanitize_string_field(payload.organization).map(|name| AS {
        number: 0, // API does not provide ASN number
        name,
    });

    let country = sanitize_string_field(payload.country);
    let city = sanitize_string_field(payload.city);

    let coordinates = match (payload.latitude, payload.longitude) {
        (Some(lat), Some(lon)) => Some(Coordinates {
            lat: lat.to_string(),
            lon: lon.to_string(),
        }),
        _ => None,
    };

    let mut risk_tags = Vec::new();
    if payload.mullvad_exit_ip == Some(true) {
        risk_tags.push(RiskTag::Other("Mullvad VPN".to_string()));
    }
    if let Some(bl) = payload.blacklisted {
        if bl.blacklisted {
            risk_tags.push(RiskTag::Other("Blacklisted".to_string()));
        }
    }

    IpResult {
        success: true,
        error: No,
        provider: PROVIDER_NAME.to_string(),
        ip: Some(parsed_ip),
        autonomous_system,
        region: Some(Region {
            country,
            region: None, // API does not provide region
            city,
            coordinates,
            time_zone: None, // API does not provide timezone
        }),
        risk: Some(Risk {
            risk: None,
            tags: if risk_tags.is_empty() {
                None
            } else {
                Some(risk_tags)
            },
        }),
        used_time: None,
    }
}