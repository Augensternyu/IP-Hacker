// src/ip_check/script/ip125_com.rs

use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, request_error_ip_result, Coordinates, IpResult, Region,
    AS,
};
use crate::ip_check::script::create_reqwest_client;
use crate::ip_check::IpCheck;
use async_trait::async_trait;
use regex::Regex;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct Ip125Com;

const PROVIDER_NAME: &str = "Ip125.com";
const API_BASE_URL: &str = "https://ip125.com/api/"; // API 本身只支持 IPv4 访问

#[derive(Deserialize, Serialize, Debug)]
struct Ip125ComApiRespPayload {
    status: String,
    country: Option<String>,
    #[serde(rename = "countryCode")]
    country_code: Option<String>, // Not directly used in IpResult, but good to have
    region: Option<String>, // Region code, e.g., "QC"
    #[serde(rename = "regionName")]
    region_name: Option<String>, // Full region name
    city: Option<String>,
    // zip: Option<String>, // Not used
    lat: Option<f64>,
    lon: Option<f64>,
    timezone: Option<String>,
    isp: Option<String>,
    org: Option<String>, // Often similar to ISP or a parent org
    #[serde(rename = "as")]
    asn_str: Option<String>, // e.g., "AS13335 Cloudflare, Inc."
    query: String,       // The IP address that was queried
    message: Option<String>, // For error messages like "invalid query"
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

fn parse_asn_from_string(asn_string_opt: Option<String>) -> (Option<u32>, Option<String>) {
    match asn_string_opt {
        Some(asn_string) => {
            let re = Regex::new(r"^(AS)?(\d+)\s*(.*)$").unwrap(); // Make "AS" prefix optional
            if let Some(caps) = re.captures(&asn_string) {
                let number = caps.get(2).and_then(|m| m.as_str().parse::<u32>().ok());
                let name = caps
                    .get(3)
                    .map(|m| m.as_str().trim().to_string())
                    .filter(|s| !s.is_empty());
                (number, name)
            } else {
                // If regex doesn't match, treat the whole string as the name if it's not purely numeric
                if asn_string.chars().all(char::is_numeric) {
                    (asn_string.parse::<u32>().ok(), None)
                } else {
                    (None, Some(asn_string))
                }
            }
        }
        None => (None, None),
    }
}

#[async_trait]
impl IpCheck for Ip125Com {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        // API itself is accessed via IPv4, but can query IPv4 or IPv6 data
        let client = match create_reqwest_client(Some(false)).await {
            // Force IPv4 for API access
            Ok(c) => c,
            Err(_) => return vec![create_reqwest_client_error(PROVIDER_NAME)],
        };

        let url = if let Some(ip_addr) = ip {
            format!("{}{}{}", API_BASE_URL, ip_addr, "?lang=zh-CN")
        } else {
            // For local IP, the API endpoint is just the base URL
            // The API will detect the client's IP (which will be IPv4 due to our client config)
            format!("{}{}", API_BASE_URL, "?lang=zh-CN")
        };

        let handle = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();

            let response = match client.get(&url).send().await {
                Ok(r) => r,
                Err(e) => return request_error_ip_result(PROVIDER_NAME, &e.to_string()),
            };

            let mut result_without_time = parse_ip125_com_resp(response).await;
            result_without_time.used_time = Some(time_start.elapsed());
            result_without_time
        });

        match handle.await {
            Ok(result) => vec![result], // This API returns a single result per request
            Err(_) => vec![request_error_ip_result(
                PROVIDER_NAME,
                "Task panicked or was cancelled.",
            )],
        }
    }
}

async fn parse_ip125_com_resp(response: Response) -> IpResult {
    if !response.status().is_success() {
        let err_msg = format!("HTTP Error: {}", response.status());
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

    let payload: Ip125ComApiRespPayload = match serde_json::from_str(&response_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = response_text.chars().take(100).collect::<String>();
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse JSON: {e}. Response snippet: '{snippet}'"),
            );
        }
    };

    if payload.status != "success" {
        let err_msg = payload
            .message
            .unwrap_or_else(|| "API status was not 'success'.".to_string());
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
    }

    let parsed_ip = match payload.query.parse::<IpAddr>() {
        Ok(ip_addr) => ip_addr,
        Err(_) => {
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse 'query' IP from API: '{}'", payload.query),
            );
        }
    };

    let country = sanitize_string_field(payload.country);
    let region_name = sanitize_string_field(payload.region_name);
    let city = sanitize_string_field(payload.city);
    let timezone = sanitize_string_field(payload.timezone);

    let (asn_number, asn_name_from_as_field) =
        parse_asn_from_string(sanitize_string_field(payload.asn_str));

    let isp_name = sanitize_string_field(payload.isp);
    let org_name = sanitize_string_field(payload.org);

    // Prefer ISP, then ORG, then the name part from 'as' field for AS name
    let final_as_name = isp_name.or(org_name).or(asn_name_from_as_field);

    let autonomous_system = final_as_name.map(|name| AS {
        number: asn_number.unwrap_or(0),
        name,
    });

    let coordinates = match (payload.lat, payload.lon) {
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
            region: region_name, // Using regionName as it's more descriptive
            city,
            coordinates,
            time_zone: timezone,
        }),
        risk: None,      // API does not provide risk information
        used_time: None, // Will be set by the caller
    }
}
