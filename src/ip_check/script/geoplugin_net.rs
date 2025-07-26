// src/ip_check/script/geoplugin_net.rs

use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, not_support_error, request_error_ip_result, Coordinates,
    IpResult, Region,
};
use crate::ip_check::script::create_reqwest_client;
use crate::ip_check::IpCheck;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct GeopluginNet;

const PROVIDER_NAME: &str = "GeoPlugin.net";
const API_URL: &str = "http://www.geoplugin.net/json.gp"; // Note: HTTP, not HTTPS

#[derive(Deserialize, Serialize, Debug)]
struct GeopluginApiRespPayload {
    #[serde(rename = "geoplugin_request")]
    ip: String,
    #[serde(rename = "geoplugin_status")]
    status: u16,
    #[serde(rename = "geoplugin_city")]
    city: Option<String>,
    #[serde(rename = "geoplugin_regionName")]
    region_name: Option<String>,
    #[serde(rename = "geoplugin_countryName")]
    country_name: Option<String>,
    #[serde(rename = "geoplugin_latitude")]
    latitude: Option<String>, // API returns these as strings
    #[serde(rename = "geoplugin_longitude")]
    longitude: Option<String>,
    #[serde(rename = "geoplugin_timezone")]
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
impl IpCheck for GeopluginNet {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            // This API only supports checking the local IP of the machine making the request.
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
                Ok(r) => parse_geoplugin_net_resp(r).await,
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

async fn parse_geoplugin_net_resp(response: Response) -> IpResult {
    let status = response.status();
    if !status.is_success() {
        let err_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown HTTP error".to_string());
        let err_msg = format!("HTTP Error {status}: {err_text}");
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

    // The API wraps the JSON in a callback function "geoplugin_(...);", we need to strip it.
    let json_text = if response_text.starts_with("geoplugin_(") && response_text.ends_with(");") {
        &response_text["geoplugin_(".len()..response_text.len() - 2]
    } else {
        &response_text
    };

    let payload: GeopluginApiRespPayload = match serde_json::from_str(json_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = json_text.chars().take(100).collect::<String>();
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse JSON: {e}. Snippet: '{snippet}'"),
            );
        }
    };

    if payload.status != 200 && payload.status != 206 {
        // 206 means partial content, but still OK
        return request_error_ip_result(
            PROVIDER_NAME,
            &format!("API returned non-200 status: {}", payload.status),
        );
    }

    let parsed_ip = match payload.ip.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Could not parse IP from API: {}", payload.ip),
            );
        }
    };

    // API is IPv4 only
    if !parsed_ip.is_ipv4() {
        return request_error_ip_result(PROVIDER_NAME, "API returned a non-IPv4 address.");
    }

    let country = sanitize_string_field(payload.country_name);
    let region = sanitize_string_field(payload.region_name);
    let city = sanitize_string_field(payload.city);
    let time_zone = sanitize_string_field(payload.timezone);

    let coordinates = match (
        sanitize_string_field(payload.latitude),
        sanitize_string_field(payload.longitude),
    ) {
        (Some(lat), Some(lon)) => Some(Coordinates { lat, lon }),
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
            time_zone,
        }),
        risk: None, // API does not provide risk information
        used_time: None,
    }
}
