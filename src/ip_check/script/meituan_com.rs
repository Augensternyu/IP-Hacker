// src/ip_check/script/meituan_com.rs

use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    Coordinates, IpResult, Region, create_reqwest_client_error, json_parse_error_ip_result,
    not_support_error, request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use reqwest::Response;
use serde::Deserialize;
use std::net::IpAddr;

pub struct MeituanCom;

const PROVIDER_NAME: &str = "Meituan.com";
// URL structure from the provided example
const API_URL_BASE: &str =
    "https://apimobile.meituan.com/locate/v2/ip/loc?client_source=yourAppKey&rgeo=true&ip=";

#[derive(Deserialize, Debug)]
struct RgeoData {
    country: Option<String>,
    province: Option<String>,
    city: Option<String>,
    district: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ApiDataPayload {
    lng: Option<f64>,
    lat: Option<f64>,
    ip: String,
    rgeo: Option<RgeoData>,
}

#[derive(Deserialize, Debug)]
struct TopLevelResp {
    // The API might not have a top-level status/code field and directly returns the data object on success.
    // If it's just the data object, we'll deserialize directly into ApiDataPayload.
    // Let's assume for now it might have a 'data' key.
    data: Option<ApiDataPayload>,
    // Add other potential top-level fields if errors return a different structure
    // e.g., code: Option<i32>, message: Option<String>
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
impl IpCheck for MeituanCom {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        // API requires a specific IP and is accessed via IPv4.
        let target_ip = match ip {
            Some(ip_addr) => {
                if ip_addr.is_ipv6() {
                    return vec![not_support_error(PROVIDER_NAME)];
                }
                ip_addr
            }
            None => return vec![not_support_error(PROVIDER_NAME)],
        };

        let handle = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            let client = match create_reqwest_client(Some(false)).await {
                // Force IPv4
                Ok(c) => c,
                Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
            };

            let url = format!("{}{}", API_URL_BASE, target_ip);
            let response_result = client.get(&url).send().await;

            let mut result = match response_result {
                Ok(r) => parse_meituan_com_resp(r).await,
                Err(e) => request_error_ip_result(PROVIDER_NAME, &e.to_string()),
            };
            result.used_time = Some(time_start.elapsed());
            result
        });

        match handle.await {
            Ok(result) => vec![result],
            Err(_) => vec![request_error_ip_result(
                PROVIDER_NAME,
                "Task panicked or was cancelled.",
            )],
        }
    }
}

async fn parse_meituan_com_resp(response: Response) -> IpResult {
    let status = response.status();
    if !status.is_success() {
        let err_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown HTTP error".to_string());
        return request_error_ip_result(
            PROVIDER_NAME,
            &format!("HTTP Error {}: {}", status, err_text),
        );
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

    // The demo shows the data is nested under a "data" key.
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

    let (country, region, city) = if let Some(rgeo) = data.rgeo {
        (
            sanitize_string_field(rgeo.country),
            sanitize_string_field(rgeo.province),
            // Prefer city, but fallback to district if city is empty/null
            sanitize_string_field(rgeo.city).or(sanitize_string_field(rgeo.district)),
        )
    } else {
        (None, None, None)
    };

    let coordinates = match (data.lat, data.lng) {
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
        autonomous_system: None, // API does not provide ASN/ISP
        region: Some(Region {
            country,
            region,
            city,
            coordinates,
            time_zone: None, // API does not provide timezone
        }),
        risk: None,
        used_time: None,
    }
}
