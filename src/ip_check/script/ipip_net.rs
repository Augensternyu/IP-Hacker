use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, not_support_error, parse_ip_error_ip_result, request_error_ip_result,
    IpResult, Region,
};
use crate::ip_check::script::create_reqwest_client;
use crate::ip_check::IpCheck;
use async_trait::async_trait;
use serde_json::Value;
use std::net::IpAddr;
use std::str::FromStr;

pub struct IpIpNet;

#[async_trait]
impl IpCheck for IpIpNet {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            return vec![not_support_error("Ipip.Net")];
        }

        let handle_v4 = tokio::spawn(async move {
            let Ok(client_v4) = create_reqwest_client(Some("curl/8.11.1"), Some(false)).await
            else {
                return create_reqwest_client_error("Ipip.Net");
            };

            let Ok(result) = client_v4.get("https://myip.ipip.net/json").send().await else {
                return request_error_ip_result("Ipip.Net", "Unable to connect to ipip.net");
            };

            let json = if let Ok(json) = result.json::<Value>().await {
                json
            } else {
                return request_error_ip_result("Ipip.Net", "Unable to parse json");
            };

            get_ipip_net_info(json).await
        });

        vec![handle_v4.await.unwrap_or(json_parse_error_ip_result(
            "Ipip.Net",
            "Unable to parse json",
        ))]
    }
}

async fn get_ipip_net_info(json: Value) -> IpResult {
    let data = if let Some(data) = json.get("data") {
        data
    } else {
        return request_error_ip_result("Ipip.Net", "Unable to parse json");
    };

    let ip = if let Some(ip) = data.get("ip") {
        if let Some(ip) = ip.as_str() {
            if let Ok(ip) = IpAddr::from_str(ip) {
                ip
            } else {
                return parse_ip_error_ip_result("Ipip.Net", "Unable to parse ip");
            }
        } else {
            return parse_ip_error_ip_result("Ipip.Net", "Unable to parse ip");
        }
    } else {
        return parse_ip_error_ip_result("Ipip.Net", "Unable to parse ip");
    };

    let location = if let Some(location) = data.get("location") {
        if let Some(location) = location.as_array() {
            location
        } else {
            return parse_ip_error_ip_result("Ipip.Net", "Unable to parse location");
        }
    } else {
        return parse_ip_error_ip_result("Ipip.Net", "Unable to parse location");
    };

    let country = if let Some(country) = location.first() {
        country.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    let region = if let Some(region) = location.get(1) {
        region.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    let city = if let Some(city) = location.get(2) {
        city.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    IpResult {
        success: true,
        error: No,
        provider: "Ipip.Net".to_string(),
        ip: Some(ip),
        autonomous_system: None,
        region: Some(Region {
            country,
            region,
            city,
            coordinates: None,
            time_zone: None,
        }),
        risk: None,
    }
}
