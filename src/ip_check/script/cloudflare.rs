use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    create_reqwest_client_error, not_support_error, parse_ip_error_ip_result, request_error_ip_result,
    IpResult,
};
use crate::ip_check::script::create_reqwest_client;
use crate::ip_check::IpCheck;
use async_trait::async_trait;
use reqwest::Response;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub struct Cloudflare;

#[async_trait]
impl IpCheck for Cloudflare {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            vec![not_support_error("Cloudflare")]
        } else {
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();

                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("Cloudflare");
                };

                let Ok(result) = client_v4
                    .get("https://cloudflare.com/cdn-cgi/trace")
                    .send()
                    .await
                else {
                    return request_error_ip_result("Cloudflare", "Unable to connect");
                };

                let mut result_without_time = get_cloudflare_info(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();

                let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error("Cloudflare");
                };

                let Ok(result) = client_v6
                    .get("https://cloudflare.com/cdn-cgi/trace")
                    .send()
                    .await
                else {
                    return request_error_ip_result("Cloudflare", "Unable to connect");
                };

                let mut result_without_time = get_cloudflare_info(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
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
        return request_error_ip_result("Cloudflare", "Unable to connect");
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
        used_time: None,
    }
}
