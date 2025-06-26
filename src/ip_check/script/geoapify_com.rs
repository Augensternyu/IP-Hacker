// src/ip_check/script/geoapify_com.rs

use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    Coordinates, IpResult, Region, create_reqwest_client_error, json_parse_error_ip_result,
    request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use reqwest::Response;
use serde::Deserialize;
use std::net::IpAddr;

pub struct GeoapifyCom;

const PROVIDER_NAME: &str = "Geoapify.com";
const API_KEY: &str = "14ab66e396a34871bc315a19447af81f";
const API_BASE_URL: &str = "https://api.geoapify.com/v1/ipinfo";

// --- Serde Structs to match the API's nested JSON response ---

#[derive(Deserialize, Debug)]
struct TopLevelResp {
    ip: String,
    city: Option<ApiNameObject>,
    country: Option<ApiNameObject>,
    location: Option<ApiLocation>,
    state: Option<ApiNameObject>,
    // Add a field to catch potential error messages
    #[serde(rename = "error")]
    api_error: Option<ApiError>,
}

#[derive(Deserialize, Debug)]
struct ApiNameObject {
    name: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ApiLocation {
    latitude: Option<f64>,
    longitude: Option<f64>,
}

#[derive(Deserialize, Debug)]
struct ApiError {
    message: String,
    // code: String,
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
impl IpCheck for GeoapifyCom {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        let url = if let Some(ip_addr) = ip {
            format!("{API_BASE_URL}?apiKey={API_KEY}&ip={ip_addr}")
        } else {
            format!("{API_BASE_URL}?apiKey={API_KEY}")
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
                    Ok(r) => parse_geoapify_com_resp(r).await,
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
            // --- Query local IP (v4 and v6) ---
            let mut results = Vec::new();

            let handle_v4 = tokio::spawn({
                let url = url.clone();
                async move {
                    let time_start = tokio::time::Instant::now();
                    let client_v4 = match create_reqwest_client(Some(false)).await {
                        Ok(c) => c,
                        Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                    };

                    let response_result_v4 = client_v4.get(&url).send().await;
                    let mut result_v4 = match response_result_v4 {
                        Ok(r) => parse_geoapify_com_resp(r).await,
                        Err(e) => {
                            request_error_ip_result(PROVIDER_NAME, &format!("IPv4 request: {e}"))
                        }
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
                        Ok(c) => c,
                        Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                    };
                    let response_result_v6 = client_v6.get(&url).send().await;
                    let mut result_v6 = match response_result_v6 {
                        Ok(r) => parse_geoapify_com_resp(r).await,
                        Err(e) => {
                            request_error_ip_result(PROVIDER_NAME, &format!("IPv6 request: {e}"))
                        }
                    };
                    result_v6.used_time = Some(time_start.elapsed());
                    result_v6
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
}

async fn parse_geoapify_com_resp(response: Response) -> IpResult {
    let status = response.status();
    let response_text = match response.text().await {
        Ok(text) => text,
        Err(e) => {
            return request_error_ip_result(
                PROVIDER_NAME,
                &format!(
                    "Failed to read response text (status was {status}): {e}"
                ),
            );
        }
    };

    // Geoapify returns 200 OK even for errors, with the error in the body.
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

    if let Some(error) = payload.api_error {
        return request_error_ip_result(PROVIDER_NAME, &error.message);
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

    let country = payload.country.and_then(|c| sanitize_string_field(c.name));
    let region = payload.state.and_then(|s| sanitize_string_field(s.name));
    let city = payload.city.and_then(|c| sanitize_string_field(c.name));

    let coordinates = payload
        .location
        .and_then(|loc| match (loc.latitude, loc.longitude) {
            (Some(lat), Some(lon)) => Some(Coordinates {
                lat: lat.to_string(),
                lon: lon.to_string(),
            }),
            _ => None,
        });

    IpResult {
        success: true,
        error: No,
        provider: PROVIDER_NAME.to_string(),
        ip: Some(parsed_ip),
        autonomous_system: None, // API does not provide ASN/ISP in demo
        region: Some(Region {
            country,
            region,
            city,
            coordinates,
            time_zone: None, // API does not provide a standard timezone ID in demo
        }),
        risk: None, // API does not provide risk information
        used_time: None,
    }
}
