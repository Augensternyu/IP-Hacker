// src/ip_check/script/reallyfreegeoip_org.rs

use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
// Corrected unused import
use crate::ip_check::ip_result::{
    Coordinates, IpResult, Region, create_reqwest_client_error, json_parse_error_ip_result,
    request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct ReallyfreegeoipOrg;

const PROVIDER_NAME: &str = "ReallyFreeGeoIP.org";
const API_BASE_URL: &str = "https://reallyfreegeoip.org/json/";

#[derive(Deserialize, Serialize, Debug)]
struct ReallyfreegeoipOrgApiRespPayload {
    ip: String,
    country_code: Option<String>,
    country_name: Option<String>,
    region_code: Option<String>,
    region_name: Option<String>,
    city: Option<String>,
    time_zone: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
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
impl IpCheck for ReallyfreegeoipOrg {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip_addr) = ip {
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let client = match create_reqwest_client(None).await {
                    Ok(c) => c,
                    Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                };

                let url = format!("{API_BASE_URL}{ip_addr}");
                let response_result = client.get(&url).send().await;

                let mut result_without_time = match response_result {
                    Ok(r) => parse_reallyfreegeoip_org_resp(r).await,
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
            let mut results = Vec::new();

            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let client_v4 = match create_reqwest_client(Some(false)).await {
                    Ok(c) => c,
                    Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                };

                let response_result_v4 = client_v4.get(API_BASE_URL).send().await;
                let mut result_v4 = match response_result_v4 {
                    Ok(r) => parse_reallyfreegeoip_org_resp(r).await,
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
                    Ok(c) => c,
                    Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                };

                let response_result_v6 = client_v6.get(API_BASE_URL).send().await;
                let mut result_v6 = match response_result_v6 {
                    Ok(r) => parse_reallyfreegeoip_org_resp(r).await,
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

async fn parse_reallyfreegeoip_org_resp(response: Response) -> IpResult {
    // Store status before consuming response for text
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
            // This case might be less likely if status.is_success() was true, but good to handle
            return request_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to read response text (status was {status}): {e}"),
            );
        }
    };

    if response_text.trim().to_lowercase() == "not found" {
        return request_error_ip_result(PROVIDER_NAME, "IP address not found by API.");
    }
    if response_text.trim().to_lowercase() == "usage limit exceeded" {
        return request_error_ip_result(PROVIDER_NAME, "API usage limit exceeded.");
    }

    let payload: ReallyfreegeoipOrgApiRespPayload = match serde_json::from_str(&response_text) {
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
    let city = sanitize_string_field(payload.city);
    let time_zone = sanitize_string_field(payload.time_zone);

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
        autonomous_system: None,
        region: Some(Region {
            country,
            region: region_name,
            city,
            coordinates,
            time_zone,
        }),
        risk: None,
        used_time: None,
    }
}
