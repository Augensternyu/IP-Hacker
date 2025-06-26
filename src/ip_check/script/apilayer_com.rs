// src/ip_check/script/apilayer_com.rs

use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    AS, Coordinates, IpResult, Region, create_reqwest_client_error, json_parse_error_ip_result,
    not_support_error, request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use reqwest::{Response, header};
use serde::Deserialize;
use std::net::IpAddr;

pub struct ApilayerCom;

const PROVIDER_NAME: &str = "Apilayer.com";
const API_BASE_URL: &str = "https://api.apilayer.com/ip_to_location/";
const API_KEY: &str = "Mk25YMojGmhBUpu422bBXR0w2UT4ihc8";

// --- Serde Structs to match the API's nested JSON response ---

#[derive(Deserialize, Debug)]
struct TopLevelResp {
    ip: String,
    // type: String, // "ipv4" or "ipv6"
    city: Option<String>,
    region_name: Option<String>,
    country_name: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    connection: Option<ApiConnection>,
    timezones: Option<Vec<String>>,
    message: Option<String>, // For error messages
}

#[derive(Deserialize, Debug)]
struct ApiConnection {
    asn: Option<u32>,
    isp: Option<String>,
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
impl IpCheck for ApilayerCom {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        let target_ip = match ip {
            Some(ip_addr) => {
                if ip_addr.is_ipv6() {
                    // Based on "supports ipv4 data" in prompt, let's assume it doesn't support v6 for now.
                    // If it does, this check can be removed.
                    return vec![not_support_error(PROVIDER_NAME)];
                }
                ip_addr
            }
            // `ip` must be specified for this provider
            None => return vec![not_support_error(PROVIDER_NAME)],
        };

        let handle = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            let client = match create_reqwest_client(None).await {
                // Default client, as API supports IPv4/6 access
                Ok(c) => c,
                Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
            };

            let url = format!("{API_BASE_URL}{target_ip}");
            let mut headers = header::HeaderMap::new();
            headers.insert("apikey", API_KEY.parse().unwrap());

            let response_result = client.get(&url).headers(headers).send().await;

            let mut result = match response_result {
                Ok(r) => parse_apilayer_com_resp(r).await,
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

async fn parse_apilayer_com_resp(response: Response) -> IpResult {
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

    if let Some(message) = payload.message {
        return request_error_ip_result(PROVIDER_NAME, &message);
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

    let autonomous_system =
        payload
            .connection
            .and_then(|conn| match (conn.asn, sanitize_string_field(conn.isp)) {
                (Some(number), Some(name)) => Some(AS { number, name }),
                (None, Some(name)) => Some(AS { number: 0, name }),
                _ => None,
            });

    let country = sanitize_string_field(payload.country_name);
    let region = sanitize_string_field(payload.region_name);
    let city = sanitize_string_field(payload.city);
    // Take the first timezone from the list if available
    let time_zone = payload.timezones.and_then(|tzs| tzs.first().cloned());

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
            region,
            city,
            coordinates,
            time_zone,
        }),
        risk: None, // API does not provide explicit risk information
        used_time: None,
    }
}
