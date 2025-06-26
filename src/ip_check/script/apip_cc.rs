// src/ip_check/script/apip_cc.rs

use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    AS, Coordinates, IpResult, Region, create_reqwest_client_error, json_parse_error_ip_result,
    request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use regex::Regex;
use reqwest::Response;
use serde::Deserialize;
use std::net::IpAddr;

pub struct ApipCc;

const PROVIDER_NAME: &str = "Apip.cc";
const API_BASE_URL_LOCAL: &str = "https://apip.cc/json";
const API_BASE_URL_SPECIFIC: &str = "https://apip.cc/api-json/";

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)] // To match the API's PascalCase field names
struct ApipCcApiRespPayload {
    status: String,
    query: String,
    CountryName: Option<String>,
    RegionName: Option<String>,
    City: Option<String>,
    Latitude: Option<String>, // API returns these as strings
    Longitude: Option<String>,
    TimeZone: Option<String>,
    asn: Option<String>, // e.g., "AS3462"
    org: Option<String>,
    message: Option<String>, // For error cases
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

fn parse_asn_number(asn_str_opt: Option<String>) -> Option<u32> {
    asn_str_opt.and_then(|s| {
        let re = Regex::new(r"^(AS)?(\d+)$").unwrap();
        if let Some(caps) = re.captures(&s) {
            caps.get(2).and_then(|m| m.as_str().parse::<u32>().ok())
        } else {
            None
        }
    })
}

#[async_trait]
impl IpCheck for ApipCc {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        // API itself is accessed via IPv4, but can query IPv4/IPv6 data
        let client = match create_reqwest_client(Some(false)).await {
            // Force IPv4 for API access
            Ok(c) => c,
            Err(_) => return vec![create_reqwest_client_error(PROVIDER_NAME)],
        };

        if let Some(ip_addr) = ip {
            // --- Query specific IP ---
            let url = format!("{API_BASE_URL_SPECIFIC}{ip_addr}");
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();

                let response_result = client.get(&url).send().await;
                let mut result_without_time = match response_result {
                    Ok(r) => parse_apip_cc_resp(r).await,
                    Err(e) => request_error_ip_result(PROVIDER_NAME, &e.to_string()),
                };
                result_without_time.used_time = Some(time_start.elapsed());
                result_without_time
            });

            match handle.await {
                Ok(result) => vec![result],
                Err(_) => vec![request_error_ip_result(
                    PROVIDER_NAME,
                    "Task panicked or was cancelled.",
                )],
            }
        } else {
            // --- Query local IP ---
            // This API has different endpoints for local v4 and v6, so we only need one call.
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();

                let response_result = client.get(API_BASE_URL_LOCAL).send().await; // Path is /json
                let mut result_without_time = match response_result {
                    Ok(r) => parse_apip_cc_resp(r).await,
                    Err(e) => request_error_ip_result(PROVIDER_NAME, &e.to_string()),
                };
                result_without_time.used_time = Some(time_start.elapsed());
                result_without_time
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
}

async fn parse_apip_cc_resp(response: Response) -> IpResult {
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

    let payload: ApipCcApiRespPayload = match serde_json::from_str(&response_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = response_text.chars().take(100).collect::<String>();
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse JSON: {e}. Snippet: '{snippet}'"),
            );
        }
    };

    if payload.status.to_lowercase() != "success" {
        let err_msg = payload
            .message
            .unwrap_or_else(|| format!("API status was not 'success': {}", payload.status));
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
    }

    let parsed_ip = match payload.query.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Could not parse IP from API: {}", payload.query),
            );
        }
    };

    let asn_number = parse_asn_number(sanitize_string_field(payload.asn));
    let as_name = sanitize_string_field(payload.org);

    let autonomous_system = match (asn_number, as_name) {
        (Some(number), Some(name)) => Some(AS { number, name }),
        (None, Some(name)) => Some(AS { number: 0, name }),
        _ => None,
    };

    let country = sanitize_string_field(payload.CountryName);
    let region = sanitize_string_field(payload.RegionName);
    let city = sanitize_string_field(payload.City);
    let time_zone = sanitize_string_field(payload.TimeZone);

    let coordinates = match (
        sanitize_string_field(payload.Latitude),
        sanitize_string_field(payload.Longitude),
    ) {
        (Some(lat), Some(lon)) => Some(Coordinates { lat, lon }),
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
        risk: None, // API does not provide risk information
        used_time: None,
    }
}
