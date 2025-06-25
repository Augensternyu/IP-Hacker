// src/ip_check/script/dashi_163_com.rs

use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    AS, Coordinates, IpResult, Region, create_reqwest_client_error, json_parse_error_ip_result,
    not_support_error, request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use reqwest::Response;
use serde::Deserialize;
use std::net::IpAddr;

pub struct Dashi163Com;

const PROVIDER_NAME: &str = "Dashi.163.com";
const API_URL: &str = "https://dashi.163.com/fgw/mailsrv-ipdetail/detail";

#[derive(Deserialize, Debug)]
struct ApiResultData {
    country: Option<String>,
    province: Option<String>,
    city: Option<String>,
    isp: Option<String>,
    latitude: Option<String>,
    longitude: Option<String>,
    timezone: Option<String>,
    ip: String,
}

#[derive(Deserialize, Debug)]
struct TopLevelResp {
    code: i32,
    #[serde(rename = "success")]
    _success: String, // This field is unreliable, ignore its value.
    result: Option<ApiResultData>,
    desc: Option<String>,
}

fn sanitize_string_field(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() || trimmed.to_uppercase() == "UNKNOWN" {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[async_trait]
impl IpCheck for Dashi163Com {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            return vec![not_support_error(PROVIDER_NAME)];
        }

        let mut results = Vec::new();

        let handle_v4 = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            let client_v4 = match create_reqwest_client(Some(false)).await {
                Ok(c) => c,
                Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
            };

            let response_result_v4 = client_v4.get(API_URL).send().await;
            let mut result_v4 = match response_result_v4 {
                Ok(r) => parse_dashi_163_com_resp(r).await,
                Err(e) => request_error_ip_result(PROVIDER_NAME, &format!("IPv4 request: {e}")),
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
            let response_result_v6 = client_v6.get(API_URL).send().await;
            let mut result_v6 = match response_result_v6 {
                Ok(r) => parse_dashi_163_com_resp(r).await,
                Err(e) => request_error_ip_result(PROVIDER_NAME, &format!("IPv6 request: {e}")),
            };
            result_v6.used_time = Some(time_start.elapsed());
            result_v6
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

async fn parse_dashi_163_com_resp(response: Response) -> IpResult {
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

    // **FIXED LOGIC**: The API's `success` field is unreliable.
    // We now consider `code == 200` as the primary success indicator.
    // The check for `payload.result`'s existence will happen next.
    if payload.code != 200 {
        let err_msg = payload
            .desc
            .unwrap_or_else(|| "API returned non-200 code.".to_string());
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
    }

    let data = match payload.result {
        Some(d) => d,
        None => {
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                "API code was 200 but 'result' field is missing.",
            );
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

    let country = sanitize_string_field(data.country);
    let region = sanitize_string_field(data.province);
    let city = sanitize_string_field(data.city);
    let isp = sanitize_string_field(data.isp);
    let time_zone = sanitize_string_field(data.timezone);

    let autonomous_system = isp.map(|name| AS { number: 0, name });

    let coordinates = match (
        sanitize_string_field(data.latitude),
        sanitize_string_field(data.longitude),
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
        risk: None,
        used_time: None,
    }
}
