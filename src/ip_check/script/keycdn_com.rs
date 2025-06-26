// src/ip_check/script/keycdn_com.rs

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

pub struct KeycdnCom;

const PROVIDER_NAME: &str = "Keycdn.com";
const API_BASE_URL: &str = "https://tools.keycdn.com/geo.json";

// --- Serde Structs to match the API's nested JSON response ---

#[derive(Deserialize, Debug)]
struct TopLevelResp {
    status: String,
    description: Option<String>,
    data: Option<ApiData>,
}

#[derive(Deserialize, Debug)]
struct ApiData {
    geo: ApiGeo,
}

#[derive(Deserialize, Debug)]
struct ApiGeo {
    ip: String,
    asn: Option<u32>,
    isp: Option<String>,
    country_name: Option<String>,
    region_name: Option<String>,
    city: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
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
impl IpCheck for KeycdnCom {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        let target_ip = match ip {
            Some(ip_addr) => ip_addr,
            // API requires a specific IP.
            None => return vec![not_support_error(PROVIDER_NAME)],
        };

        let handle = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            let client = match create_reqwest_client(None).await {
                Ok(c) => c,
                Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
            };

            let url = format!("{API_BASE_URL}?host={target_ip}");
            let mut headers = header::HeaderMap::new();
            // The User-Agent is critical for this API.
            headers.insert(
                header::USER_AGENT,
                "keycdn-tools:https://yoursite.com".parse().unwrap(),
            );

            let response_result = client.get(&url).headers(headers).send().await;

            let mut result = match response_result {
                Ok(r) => parse_keycdn_com_resp(r).await,
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

async fn parse_keycdn_com_resp(response: Response) -> IpResult {
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

    if payload.status != "success" {
        let err_msg = payload
            .description
            .unwrap_or_else(|| "API status was not 'success'.".to_string());
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
    }

    let geo_data = match payload.data {
        Some(data) => data.geo,
        None => {
            return json_parse_error_ip_result(PROVIDER_NAME, "API response missing 'data' field.");
        }
    };

    let parsed_ip = match geo_data.ip.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Could not parse IP from API: {}", geo_data.ip),
            );
        }
    };

    let autonomous_system = match (geo_data.asn, sanitize_string_field(geo_data.isp)) {
        (Some(number), Some(name)) => Some(AS { number, name }),
        (None, Some(name)) => Some(AS { number: 0, name }),
        _ => None,
    };

    let country = sanitize_string_field(geo_data.country_name);
    let region = sanitize_string_field(geo_data.region_name);
    let city = sanitize_string_field(geo_data.city);
    let time_zone = sanitize_string_field(geo_data.timezone);

    let coordinates = match (geo_data.latitude, geo_data.longitude) {
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
        risk: None, // API does not provide risk information
        used_time: None,
    }
}
