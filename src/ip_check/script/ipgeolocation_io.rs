use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, request_error_ip_result,
    Coordinates, IpResult, Region,
};
use crate::ip_check::script::create_reqwest_client;
use crate::ip_check::IpCheck;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct IpgeolocationIo;

const API_KEY: &str = "14c7928d2aef416287e034ee91cd360d";
const BROWSER_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

#[async_trait]
impl IpCheck for IpgeolocationIo {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        // API不支持IPv6访问, 所有请求强制走IPv4
        if let Some(ip) = ip {
            // --- 检查指定IP ---
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client) = create_reqwest_client(Some(BROWSER_USER_AGENT), Some(false)).await else {
                    return create_reqwest_client_error("IpGeolocation.io");
                };

                let url = format!("https://api.ipgeolocation.io/v2/ipgeo?apiKey={API_KEY}&ip={ip}");
                let Ok(result) = client.get(url).send().await else {
                    return request_error_ip_result("IpGeolocation.io", "Unable to connect");
                };

                let mut result_without_time = parse_ipgeolocation_io_resp(result).await;
                result_without_time.used_time = Some(time_start.elapsed());
                result_without_time
            });
            vec![handle.await.unwrap()]
        } else {
            // --- 检查本机IP ---
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v4) = create_reqwest_client(Some(BROWSER_USER_AGENT), Some(false)).await else {
                    return create_reqwest_client_error("IpGeolocation.io");
                };

                let url = format!("https://api.ipgeolocation.io/v2/ipgeo?apiKey={API_KEY}");
                let Ok(result) = client_v4.get(url).send().await else {
                    return request_error_ip_result("IpGeolocation.io", "Unable to connect");
                };

                let mut result_without_time = parse_ipgeolocation_io_resp(result).await;
                result_without_time.used_time = Some(time_start.elapsed());
                result_without_time
            });

            vec![handle_v4.await.unwrap()]
        }
    }
}

async fn parse_ipgeolocation_io_resp(response: Response) -> IpResult {
    #[derive(Deserialize, Serialize)]
    struct Resp {
        ip: Option<IpAddr>,
        location: Option<LocationData>,
        message: Option<String>, // 用于捕获API的错误信息
    }
    #[derive(Deserialize, Serialize)]
    struct LocationData {
        country_name: Option<String>,
        state_prov: Option<String>,
        city: Option<String>,
        latitude: Option<String>,
        longitude: Option<String>,
    }

    let Ok(json) = response.json::<Resp>().await else {
        return json_parse_error_ip_result("IpGeolocation.io", "Unable to parse result into Json");
    };

    if let Some(msg) = json.message {
        return request_error_ip_result("IpGeolocation.io", &msg);
    }

    if json.ip.is_none() {
        return request_error_ip_result("IpGeolocation.io", "API response did not contain an IP address.");
    }

    let location = json.location;

    IpResult {
        success: true,
        error: No,
        provider: "IpGeolocation.io".to_string(),
        ip: json.ip,
        autonomous_system: None, // API不提供ASN/ISP信息
        region: {
            location.map(|loc| Region {
                country: loc.country_name,
                region: loc.state_prov,
                city: loc.city,
                coordinates: if let (Some(lat), Some(lon)) = (loc.latitude, loc.longitude) {
                    Some(Coordinates { lat, lon })
                } else {
                    None
                },
                time_zone: None, // API不提供标准时区标识
            })
        },
        risk: None, // API不提供风险信息
        used_time: None,
    }
}