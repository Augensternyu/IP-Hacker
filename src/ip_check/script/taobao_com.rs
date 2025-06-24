// src/ip_check/script/taobao_com.rs

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

pub struct TaobaoCom;

const PROVIDER_NAME: &str = "Taobao.com";
// URL structure from provided example
const API_URL_BASE: &str = "https://ip.taobao.com/outGetIpInfo?accessKey=alibaba-inc&ip=";

#[derive(Deserialize, Debug)]
struct ApiDataPayload {
    country: Option<String>,
    region: Option<String>, // province
    city: Option<String>,
    isp: Option<String>,
    ip: String,
}

#[derive(Deserialize, Debug)]
struct TopLevelResp {
    code: i32,
    msg: String,
    data: Option<ApiDataPayload>,
}

fn sanitize_string_field(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() || trimmed == "XX" {
            // Taobao API uses "XX" for unknown ISP
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[async_trait]
impl IpCheck for TaobaoCom {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        // This API only supports checking a specific IP and is accessed via IPv4.
        let target_ip = match ip {
            Some(ip_addr) => {
                if ip_addr.is_ipv6() {
                    // The API seems to be for IPv4 only based on examples and common knowledge.
                    return vec![not_support_error(PROVIDER_NAME)];
                }
                ip_addr
            }
            // `ip` must be specified for this provider
            None => return vec![not_support_error(PROVIDER_NAME)],
        };

        let handle = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            // Force IPv4 for API access as it's an older API
            let client = match create_reqwest_client(Some(false)).await {
                Ok(c) => c,
                Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
            };

            let url = format!("{}{}", API_URL_BASE, target_ip);
            let response_result = client.get(&url).send().await;

            let mut result = match response_result {
                Ok(r) => parse_taobao_com_resp(r).await,
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

async fn parse_taobao_com_resp(response: Response) -> IpResult {
    let status = response.status();
    if !status.is_success() {
        let err_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown HTTP error".to_string());
        return request_error_ip_result(
            PROVIDER_NAME,
            &format!("HTTP Error {}: {}", status, err_text),
        );
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

    if payload.code != 0 {
        return request_error_ip_result(PROVIDER_NAME, &payload.msg);
    }

    let data = match payload.data {
        Some(d) => d,
        None => {
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                "API code was 0 but 'data' field is missing.",
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
    let region = sanitize_string_field(data.region);
    let city = sanitize_string_field(data.city);
    let isp = sanitize_string_field(data.isp);

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
            coordinates: None, // API does not provide coordinates
            time_zone: None,   // API does not provide timezone
        }),
        risk: None,
        used_time: None,
    }
}
