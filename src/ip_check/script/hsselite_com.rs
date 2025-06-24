// src/ip_check/script/hsselite_com.rs

use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    AS, Coordinates, IpResult, Region, create_reqwest_client_error, json_parse_error_ip_result,
    not_support_error, request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use reqwest::Response;
use serde::Deserialize;
use std::net::IpAddr;

pub struct HsseliteCom;

const PROVIDER_NAME: &str = "Hsselite.com";
const API_URL: &str = "https://www.hsselite.com/ipinfo";

#[derive(Deserialize, Debug)]
struct HsseliteComApiRespPayload {
    asn: Option<u32>,
    // aso: Option<String>, // Redundant with organization or isp
    city: Option<String>,
    // continent_code: Option<String>,
    // country_code: Option<String>,
    country_name: Option<String>,
    ip: String,
    // is_hotspotshield_connected: bool, // Could be a risk tag if needed
    isp: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    organization: Option<String>,
    region: Option<String>, // This is a region code, not full name
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
impl IpCheck for HsseliteCom {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            // This API only supports checking the local IP.
            return vec![not_support_error(PROVIDER_NAME)];
        }

        // --- Query local IP (only IPv4 is supported by the API) ---
        let handle_v4 = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            let client_v4 = match create_reqwest_client(Some(false)).await {
                // Force IPv4
                Ok(c) => c,
                Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
            };

            let response_result = client_v4.get(API_URL).send().await;
            let mut result = match response_result {
                Ok(r) => parse_hsselite_com_resp(r).await,
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

async fn parse_hsselite_com_resp(response: Response) -> IpResult {
    let status = response.status();
    if !status.is_success() {
        let err_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown HTTP error".to_string());
        let err_msg = format!("HTTP Error {}: {}", status, err_text);
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
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

    let payload: HsseliteComApiRespPayload = match serde_json::from_str(&response_text) {
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

    if !parsed_ip.is_ipv4() {
        return request_error_ip_result(PROVIDER_NAME, "API returned a non-IPv4 address.");
    }

    let as_name =
        sanitize_string_field(payload.isp).or(sanitize_string_field(payload.organization));

    let autonomous_system = match (payload.asn, as_name) {
        (Some(number), Some(name)) => Some(AS { number, name }),
        (None, Some(name)) => Some(AS { number: 0, name }),
        _ => None,
    };

    let country = sanitize_string_field(payload.country_name);
    let region = sanitize_string_field(payload.region);
    let city = sanitize_string_field(payload.city);

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
            region, // Note: This is a region code like "TPE"
            city,
            coordinates,
            time_zone: None, // API does not provide timezone
        }),
        risk: None, // API does not provide explicit risk flags, besides the hotspotshield one
        used_time: None,
    }
}
