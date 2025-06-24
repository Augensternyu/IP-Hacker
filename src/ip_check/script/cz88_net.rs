// src/ip_check/script/cz88_net.rs

use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::RiskTag::{Hosting, Other, Proxy, Tor};
use crate::ip_check::ip_result::{
    AS, Coordinates, IpResult, Region, Risk, create_reqwest_client_error,
    json_parse_error_ip_result, not_support_error, request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;

pub struct Cz88Net;

const PROVIDER_NAME: &str = "Cz88.net";

#[derive(Deserialize, Serialize, Debug)]
struct Cz88NetApiLocation {
    latitude: Option<String>,
    longitude: Option<String>,
    // radius: Option<u32>, // Not used
}

#[derive(Deserialize, Serialize, Debug)]
struct Cz88NetApiDataPayload {
    ip: String,
    country: Option<String>,
    province: Option<String>,
    city: Option<String>,
    isp: Option<String>,
    asn: Option<String>,     // More like a label or org name
    company: Option<String>, // Also an org name
    locations: Option<Vec<Cz88NetApiLocation>>,
    score: Option<String>, // Trust score, string "0"-"100"
    vpn: Option<bool>,
    tor: Option<bool>,
    proxy: Option<bool>,
    #[serde(rename = "icloudPrivateRelay")]
    icloud_private_relay: Option<bool>,
    #[serde(rename = "netWorkType")]
    net_work_type: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
struct Cz88NetApiRespPayload {
    code: i32,
    success: bool,
    message: Option<String>,
    data: Option<Cz88NetApiDataPayload>,
    // time: Option<String>, // Not used
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
impl IpCheck for Cz88Net {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        let ip_addr = match ip {
            Some(i) => i,
            None => return vec![not_support_error(PROVIDER_NAME)], // API requires a specific IP
        };

        let handle = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();

            let client = match create_reqwest_client(None).await {
                // Default client
                Ok(c) => c,
                Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
            };

            let url = format!("https://update.cz88.net/api/cz88/ip/base?ip={ip_addr}");
            let response = match client.get(url).send().await {
                Ok(r) => r,
                Err(e) => return request_error_ip_result(PROVIDER_NAME, &e.to_string()),
            };

            let mut result_without_time = parse_cz88_net_resp(response, ip_addr).await; // Pass ip_addr for context if needed
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

async fn parse_cz88_net_resp(response: Response, _original_ip: IpAddr) -> IpResult {
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

    let payload: Cz88NetApiRespPayload = match serde_json::from_str(&response_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = response_text.chars().take(100).collect::<String>();
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse JSON: {e}. Response snippet: '{snippet}'"),
            );
        }
    };

    if !(payload.code == 200 && payload.success) {
        let err_msg = payload
            .message
            .unwrap_or_else(|| "API indicated failure.".to_string());
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
    }

    let data = match payload.data {
        Some(d) => d,
        None => {
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                "API success but 'data' field is missing.",
            );
        }
    };

    let parsed_ip = match data.ip.parse::<IpAddr>() {
        Ok(ip_addr) => ip_addr,
        Err(_) => {
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse IP string from API data: '{}'", data.ip),
            );
        }
    };

    let country = sanitize_string_field(data.country);
    let province = sanitize_string_field(data.province);
    let city = sanitize_string_field(data.city);

    let isp_name_opt = sanitize_string_field(data.isp);
    let company_name_opt = sanitize_string_field(data.company);
    let asn_label_opt = sanitize_string_field(data.asn); // API's 'asn' is more of a label

    let as_name = isp_name_opt.or(company_name_opt).or(asn_label_opt);

    let autonomous_system = as_name.map(|name| AS {
        number: 0, // API does not provide a clear numeric ASN
        name,
    });

    let coordinates = data.locations.and_then(|locs| {
        locs.first().and_then(|loc| {
            match (
                sanitize_string_field(loc.latitude.clone()),
                sanitize_string_field(loc.longitude.clone()),
            ) {
                (Some(lat), Some(lon)) => Some(Coordinates { lat, lon }),
                _ => None,
            }
        })
    });

    let risk_score = data
        .score
        .and_then(|s| s.parse::<u16>().ok())
        .map(|trust_score| {
            if trust_score > 100 {
                100
            } else {
                100 - trust_score
            } // Convert trust score to risk score
        });

    let mut risk_tags_set = HashSet::new();
    if data.vpn == Some(true) {
        risk_tags_set.insert(Proxy);
    }
    if data.tor == Some(true) {
        risk_tags_set.insert(Tor);
    }
    if data.proxy == Some(true) {
        risk_tags_set.insert(Proxy);
    }
    if data.icloud_private_relay == Some(true) {
        risk_tags_set.insert(Other("iCloud Relay".to_string()));
    }
    if let Some(net_type) = sanitize_string_field(data.net_work_type) {
        if net_type == "数据中心" {
            risk_tags_set.insert(Hosting);
        } else if !net_type.is_empty() {
            // Optionally add other network types if desired
            // risk_tags_set.insert(Other(net_type.to_uppercase()));
        }
    }
    let risk_tags_vec: Vec<_> = risk_tags_set.into_iter().collect();

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
            time_zone: None, // API does not provide timezone
        }),
        risk: Some(Risk {
            risk: risk_score,
            tags: if risk_tags_vec.is_empty() {
                None
            } else {
                Some(risk_tags_vec)
            },
        }),
        used_time: None, // Will be set by the caller
    }
}
