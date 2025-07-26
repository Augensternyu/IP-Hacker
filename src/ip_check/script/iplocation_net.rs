// src/ip_check/script/iplocation_net.rs

use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, not_support_error, request_error_ip_result, IpResult,
    Region, AS,
};
use crate::ip_check::script::create_reqwest_client;
use crate::ip_check::IpCheck;
use async_trait::async_trait;
use reqwest::Response;
use serde::Deserialize;
use std::net::IpAddr;

pub struct IplocationNet;

const PROVIDER_NAME: &str = "Iplocation.net";
const API_BASE_URL: &str = "https://api.iplocation.net/?ip=";

#[derive(Deserialize, Debug)]
struct IplocationNetApiRespPayload {
    ip: String,
    country_name: Option<String>,
    isp: Option<String>,
    response_code: String,
    response_message: String,
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
impl IpCheck for IplocationNet {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        let target_ip = match ip {
            Some(ip_addr) => ip_addr,
            // API requires a specific IP.
            None => return vec![not_support_error(PROVIDER_NAME)],
        };

        let handle = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            // API can be accessed via IPv4 or IPv6, client choice is default
            let client = match create_reqwest_client(None).await {
                Ok(c) => c,
                Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
            };

            let url = format!("{API_BASE_URL}{target_ip}");
            let response_result = client.get(&url).send().await;

            let mut result_without_time = match response_result {
                Ok(r) => parse_iplocation_net_resp(r).await,
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

async fn parse_iplocation_net_resp(response: Response) -> IpResult {
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

    let payload: IplocationNetApiRespPayload = match serde_json::from_str(&response_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = response_text.chars().take(100).collect::<String>();
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse JSON: {e}. Snippet: '{snippet}'"),
            );
        }
    };

    // Check the API's internal response code
    if payload.response_code != "200" {
        return request_error_ip_result(PROVIDER_NAME, &payload.response_message);
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

    let country = sanitize_string_field(payload.country_name);
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
            // API does not provide region, city, coordinates, or timezone
            region: None,
            city: None,
            coordinates: None,
            time_zone: None,
        }),
        risk: None, // API does not provide risk information
        used_time: None,
    }
}
