// src/ip_check/script/qq_com.rs

use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    AS, IpResult, Region, create_reqwest_client_error, json_parse_error_ip_result,
    not_support_error, request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use reqwest::Response;
use serde::Deserialize;
use std::net::IpAddr;

pub struct QqCom;

const PROVIDER_NAME: &str = "QQ";
const API_URL: &str = "https://r.inews.qq.com/api/ip2city?otype=json";

#[derive(Deserialize, Debug)]
struct QqComApiRespPayload {
    ret: i32,
    #[serde(rename = "errMsg")]
    err_msg: Option<String>,
    ip: String,
    country: Option<String>,
    province: Option<String>,
    city: Option<String>,
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
impl IpCheck for QqCom {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            // This API only supports checking the local IP.
            return vec![not_support_error(PROVIDER_NAME)];
        }

        // --- Query local IP (try IPv4 and IPv6) ---
        let mut results = Vec::new();

        let handle_v4 = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            let client_v4 = match create_reqwest_client(Some(false)).await {
                // Force IPv4
                Ok(c) => c,
                Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
            };

            let response_result_v4 = client_v4.get(API_URL).send().await;
            let mut result_v4 = match response_result_v4 {
                Ok(r) => parse_qq_com_resp(r).await,
                Err(e) => request_error_ip_result(PROVIDER_NAME, &format!("IPv4 request: {e}")),
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
            let response_result_v6 = client_v6.get(API_URL).send().await;
            let mut result_v6 = match response_result_v6 {
                Ok(r) => parse_qq_com_resp(r).await,
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

async fn parse_qq_com_resp(response: Response) -> IpResult {
    let status = response.status();
    if !status.is_success() {
        let err_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown HTTP error".to_string());
        let err_msg = format!("HTTP Error {}: {}", status, err_text);
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
    }

    // The API might return non-JSON with a callback wrapper, e.g., "callback({...})"
    // Need to handle this case.
    let response_text = match response.text().await {
        Ok(text) => text,
        Err(e) => {
            return request_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to read response text: {e}"),
            );
        }
    };

    // Extract JSON from potential "callback(...)" wrapper
    let json_text = if response_text.starts_with("callback(") && response_text.ends_with(')') {
        &response_text["callback(".len()..response_text.len() - 1]
    } else {
        &response_text
    };

    let payload: QqComApiRespPayload = match serde_json::from_str(json_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = json_text.chars().take(100).collect::<String>();
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse JSON: {e}. Snippet: '{snippet}'"),
            );
        }
    };

    if payload.ret != 0 {
        let err_msg = sanitize_string_field(payload.err_msg)
            .unwrap_or_else(|| "API returned non-zero status.".to_string());
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
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

    let country = sanitize_string_field(payload.country);
    let region = sanitize_string_field(payload.province);
    let city = sanitize_string_field(payload.city);
    let isp = sanitize_string_field(payload.isp);

    let autonomous_system = isp.map(|name| AS { number: 0, name });

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
            coordinates: None,
            time_zone: None,
        }),
        risk: None,
        used_time: None,
    }
}
