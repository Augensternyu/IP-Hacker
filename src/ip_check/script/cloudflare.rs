use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use async_trait::async_trait;
use reqwest::Response;
use crate::ip_check::ip_result::{create_reqwest_client_error, not_support_error, parse_ip_error_ip_result, request_error_ip_result, IpResult};
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::IpCheck;
use crate::ip_check::script::create_reqwest_client;

pub struct Cloudflare;

#[async_trait]
impl IpCheck for Cloudflare {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            vec![not_support_error("Cloudflare")]
        } else {
            let handle_v4 = tokio::spawn(async move {
                let Ok(client_v4) = create_reqwest_client(Some("curl/8.11.1"), Some(false)).await else {
                    return create_reqwest_client_error("Cloudflare");
                };

                let Ok(result) = client_v4.get("https://1.0.0.1/cdn-cgi/trace").send().await else {
                    return request_error_ip_result("Cloudflare", "Unable to connect to cloudflare");
                };

                get_cloudflare_info(result).await
            });

            let handle_v6 = tokio::spawn(async move {
                let Ok(client_v4) = create_reqwest_client(Some("curl/8.11.1"), Some(true)).await else {
                    return create_reqwest_client_error("Cloudflare");
                };

                let Ok(result) = client_v4.get("https://[2606:4700:4700::1111]/cdn-cgi/trace").send().await else {
                    return request_error_ip_result("Cloudflare", "Unable to connect to cloudflare");
                };

                get_cloudflare_info(result).await
            });

            let mut results = Vec::new();
            if let Ok(result) = handle_v4.await {
                results.push(result);
            }
            if let Ok(result) = handle_v6.await {
                results.push(result);
            }
            results
        }
    }
}

async fn get_cloudflare_info(response: Response) -> IpResult {
    if !response.status().is_success() {
        return request_error_ip_result("Cloudflare", "Unable to connect to cloudflare");
    }
    let Ok(html) = response.text().await else {
        return parse_ip_error_ip_result("Cloudflare", "Unable to parse html");
    };

    let mut ip = String::new();
    for line in html.lines() {
        if line.starts_with("ip=") {
            ip = line.split('=').collect::<Vec<&str>>()[1].to_string();
            break;
        }
    }

    let ip = match Ipv4Addr::from_str(ip.as_str()) {
        Ok(ip) => IpAddr::V4(ip),
        Err(_) => match Ipv6Addr::from_str(ip.as_str()) {
            Ok(ip) => IpAddr::V6(ip),
            Err(_) => {
                return parse_ip_error_ip_result("Cloudflare", "Unable to parse ip");
            }
        },
    };
    IpResult {
        success: true,
        error: No,
        provider: "Cloudflare".to_string(),
        ip: Some(ip),
        autonomous_system: None,
        region: None,
        risk: None,
    }
}