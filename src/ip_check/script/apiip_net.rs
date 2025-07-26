// src/ip_check/script/apiip_net.rs

use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, request_error_ip_result, Coordinates, IpResult,
    Region,
};
use crate::ip_check::script::create_reqwest_client;
use crate::ip_check::IpCheck;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct ApiipNet;

const PROVIDER_NAME: &str = "Apiip.net";
const API_KEY: &str = "3cfeed82-9b17-4b57-996f-65d11429120a";
const API_BASE_URL: &str = "https://apiip.net/api/check";

#[derive(Deserialize, Serialize, Debug)]
struct ApiipNetApiRespPayload {
    ip: String,
    #[serde(rename = "countryName")]
    country_name: Option<String>,
    #[serde(rename = "regionName")]
    region_name: Option<String>,
    city: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    // The user's demo shows no timezone, ISP, or ASN fields.
    // We add a 'message' field to catch potential JSON-formatted error messages.
    message: Option<String>,
}

fn sanitize_string_field(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim();
        // Handle empty strings and explicit "null" strings
        if trimmed.is_empty() || trimmed.to_lowercase() == "null" {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[async_trait]
impl IpCheck for ApiipNet {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        let url = if let Some(ip_addr) = ip {
            format!("{API_BASE_URL}?accessKey={API_KEY}&ip={ip_addr}")
        } else {
            format!("{API_BASE_URL}?accessKey={API_KEY}")
        };

        if ip.is_some() {
            // --- Query specific IP ---
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let client = match create_reqwest_client(None).await {
                    // Default client
                    Ok(c) => c,
                    Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                };

                let response_result = client.get(&url).send().await;

                let mut result_without_time = match response_result {
                    Ok(r) => parse_apiip_net_resp(r).await,
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

            let handle_v4 = tokio::spawn({
                let url = url.clone();
                async move {
                    let time_start = tokio::time::Instant::now();
                    let client_v4 = match create_reqwest_client(Some(false)).await {
                        // Force IPv4
                        Ok(c) => c,
                        Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                    };

                    let response_result_v4 = client_v4.get(&url).send().await;
                    let mut result_v4 = match response_result_v4 {
                        Ok(r) => parse_apiip_net_resp(r).await,
                        Err(e) => request_error_ip_result(
                            PROVIDER_NAME,
                            &format!("IPv4 request failed: {e}"),
                        ),
                    };

                    result_v4.used_time = Some(time_start.elapsed());
                    result_v4
                }
            });

            let handle_v6 = tokio::spawn({
                let url = url.clone();
                async move {
                    let time_start = tokio::time::Instant::now();
                    let client_v6 = match create_reqwest_client(Some(true)).await {
                        // Force IPv6
                        Ok(c) => c,
                        Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                    };

                    let response_result_v6 = client_v6.get(&url).send().await;
                    let mut result_v6 = match response_result_v6 {
                        Ok(r) => parse_apiip_net_resp(r).await,
                        Err(e) => request_error_ip_result(
                            PROVIDER_NAME,
                            &format!("IPv6 request failed: {e}"),
                        ),
                    };
                    result_v6.used_time = Some(time_start.elapsed());
                    result_v6
                }
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

async fn parse_apiip_net_resp(response: Response) -> IpResult {
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
        let err_msg = format!(
            "HTTP Error {}: {}",
            status,
            response_text.chars().take(200).collect::<String>()
        );
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
    }

    let payload: ApiipNetApiRespPayload = match serde_json::from_str(&response_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = response_text.chars().take(100).collect::<String>();
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse JSON: {e}. Response snippet: '{snippet}'"),
            );
        }
    };

    // The API might return 200 OK but with an error message in the body, e.g., for private addresses.
    if let Some(message) = payload.message {
        if message.to_lowercase().contains("error") || message.contains("private ip address") {
            return request_error_ip_result(PROVIDER_NAME, &message);
        }
    }

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
        autonomous_system: None, // Demo does not provide ASN/ISP info
        region: Some(Region {
            country,
            region: region_name,
            city,
            coordinates,
            time_zone: None, // Demo does not provide timezone
        }),
        risk: None,      // Demo does not provide risk information
        used_time: None, // Will be set by the caller
    }
}
