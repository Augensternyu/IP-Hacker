// src/ip_check/script/realip_cc.rs

use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, request_error_ip_result, Coordinates, IpResult, Region,
    AS,
};
use crate::ip_check::script::create_reqwest_client;
use crate::ip_check::IpCheck;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct RealipCc;

const PROVIDER_NAME: &str = "Realip.cc";
const API_BASE_URL_LOCAL: &str = "https://realip.cc/json"; // For local IP
const API_BASE_URL_SPECIFIC: &str = "https://realip.cc/"; // For specific IP, note the path

#[derive(Deserialize, Serialize, Debug)]
struct RealipCcApiRespPayload {
    ip: String,
    city: Option<String>,
    province: Option<String>, // "regionName" equivalent
    country: Option<String>,
    // continent: Option<String>,
    isp: Option<String>, // Can be ASN name or ISP name
    time_zone: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    // postal_code: Option<String>,
    // iso_code: Option<String>,
    // notice: Option<String>,
    // provider: Option<String>,
    // -- Other fields not directly used by IpResult
}

fn sanitize_string_field(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim();
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
impl IpCheck for RealipCc {
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
                // For specific IP, the URL structure is different: realip.cc/?ip=...
                // The API seems to expect the IP in the query parameter and might not need /json path
                // However, the example shows "?ip=" which implies it might redirect or directly serve JSON based on Accept header or UA.
                // Let's try sending to realip.cc/ and adding ?ip=...
                // If it doesn't return JSON directly, we might need to adjust or check if it needs specific headers.
                // The provided example "https://realip.cc/?ip=..." suggests it serves JSON directly for this path.
                let url = format!("{API_BASE_URL_SPECIFIC}?ip={ip_addr}");

                let response_result = client
                    .get(&url)
                    .header("Accept", "application/json") // Explicitly request JSON
                    .send()
                    .await;

                let mut result_without_time = match response_result {
                    Ok(r) => parse_realip_cc_resp(r).await,
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

                let response_result_v4 = client_v4.get(API_BASE_URL_LOCAL).send().await; // Uses /json path
                let mut result_v4 = match response_result_v4 {
                    Ok(r) => parse_realip_cc_resp(r).await,
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

                let response_result_v6 = client_v6.get(API_BASE_URL_LOCAL).send().await; // Uses /json path
                let mut result_v6 = match response_result_v6 {
                    Ok(r) => parse_realip_cc_resp(r).await,
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

async fn parse_realip_cc_resp(response: Response) -> IpResult {
    let status = response.status();

    if !status.is_success() {
        // The API might return plain text error or non-JSON for some errors
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

    // Check for common plain text errors if API returns them
    if response_text.to_lowercase().contains("error")
        && !response_text.trim_start().starts_with('{')
    {
        return request_error_ip_result(
            PROVIDER_NAME,
            &format!(
                "API returned plain text error. Snippet: '{}'",
                response_text.chars().take(100).collect::<String>()
            ),
        );
    }

    let payload: RealipCcApiRespPayload = match serde_json::from_str(&response_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = response_text.chars().take(100).collect::<String>();
            // If the response text contains "notice", it might be a successful JSON response even if other fields are null
            // This is a bit of a heuristic for this specific API's "null-heavy" success responses.
            if response_text.contains("\"notice\":") && response_text.contains("\"ip\":") {
                // Try to salvage IP if possible, even if full parse fails due to unexpected nulls in other fields Serde might choke on
                if let Ok(partial_payload) =
                    serde_json::from_str::<serde_json::Value>(&response_text)
                {
                    if let Some(ip_val) = partial_payload.get("ip").and_then(|v| v.as_str()) {
                        if let Ok(ip_addr) = ip_val.parse::<IpAddr>() {
                            // Return a minimal success if we got an IP but couldn't parse the rest
                            return IpResult {
                                success: true,
                                error: No,
                                provider: PROVIDER_NAME.to_string(),
                                ip: Some(ip_addr),
                                // ... other fields None ...
                                autonomous_system: None,
                                region: None,
                                risk: None,
                                used_time: None,
                            };
                        }
                    }
                }
            }
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

    let country = sanitize_string_field(payload.country);
    let province = sanitize_string_field(payload.province); // regionName equivalent
    let city = sanitize_string_field(payload.city);
    let time_zone = sanitize_string_field(payload.time_zone);

    // The 'isp' field can sometimes be just an ASN (like "CLOUDFLARENET") or a full name.
    // We'll treat it as the AS name. API doesn't provide a separate ASN number.
    let autonomous_system = sanitize_string_field(payload.isp).map(|name| AS {
        number: 0, // No ASN number provided
        name,
    });

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
            region: province,
            city,
            coordinates,
            time_zone,
        }),
        risk: None,      // API does not provide explicit risk information
        used_time: None, // Will be set by the caller
    }
}
