use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::RiskTag::Tor;
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, not_support_error, request_error_ip_result, IpResult, Region,
    Risk, AS,
};
use crate::ip_check::script::create_reqwest_client;
use crate::ip_check::IpCheck;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct MyIpWtf;

#[async_trait]
impl IpCheck for MyIpWtf {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            vec![not_support_error("MyIP.wtf")]
        } else {
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("MyIP.wtf");
                };

                let Ok(result) = client_v4.get("https://myip.wtf/json").send().await else {
                    return request_error_ip_result("MyIP.wtf", "Unable to connect");
                };

                let mut result_without_time = parse_myip_wtf_resp(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error("MyIP.wtf");
                };

                let Ok(result) = client_v6.get("https://myip.wtf/json").send().await else {
                    return request_error_ip_result("MyIP.wtf", "Unable to connect");
                };

                let mut result_without_time = parse_myip_wtf_resp(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            let mut results = Vec::new();
            if let Ok(result) = handle_v4.await {
                if result.success {
                    results.push(result);
                }
            }
            if let Ok(result) = handle_v6.await {
                if result.success {
                    results.push(result);
                }
            }
            results
        }
    }
}

async fn parse_myip_wtf_resp(response: Response) -> IpResult {
    #[derive(Deserialize, Serialize)]
    struct MyIpWtfResp {
        #[serde(rename = "YourFuckingIPAddress")]
        ip: Option<IpAddr>,

        #[serde(rename = "YourFuckingLocation")]
        location: Option<String>,

        #[serde(rename = "YourFuckingISP")]
        isp: Option<String>,

        #[serde(rename = "YourFuckingTorExit")]
        is_tor: Option<bool>,

        #[serde(rename = "YourFuckingCity")]
        city: Option<String>,

        #[serde(rename = "YourFuckingCountry")]
        country: Option<String>,
    }

    if !response.status().is_success() {
        return request_error_ip_result("MyIP.wtf", "Server returned an error");
    }

    let Ok(json) = response.json::<MyIpWtfResp>().await else {
        return json_parse_error_ip_result(
            "MyIP.wtf",
            "Unable to parse the returned result into Json",
        );
    };

    let region = if let Some(location) = json.location {
        let parts: Vec<&str> = location.split(", ").collect();
        // "Nanning, GX, China" -> parts[1] is "GX"
        parts.get(1).map(|s| (*s).to_string())
    } else {
        None
    };

    IpResult {
        success: true,
        error: No,
        provider: "MyIP.wtf".to_string(),
        ip: json.ip,
        autonomous_system: {
            json.isp.map(|isp| AS {
                number: 0,
                name: isp,
            })
        },
        region: Some(Region {
            country: json.country,
            region,
            city: json.city,
            coordinates: None,
            time_zone: None,
        }),
        risk: Some(Risk {
            risk: None,
            tags: {
                if Some(true) == json.is_tor {
                    Some(vec![Tor])
                } else {
                    None
                }
            },
        }),
        used_time: None,
    }
}
