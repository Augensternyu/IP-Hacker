use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    AS, Coordinates, IpResult, Region, create_reqwest_client_error, json_parse_error_ip_result,
    request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct IpwhoIs;

#[async_trait]
impl IpCheck for IpwhoIs {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        // This API does not support being accessed over IPv6, so all handles will force IPv4.
        if let Some(ip) = ip {
            // --- 检查指定IP ---
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // 强制使用IPv4进行API访问
                let Ok(client) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("Ipwho.is");
                };

                let url = format!("https://ipwho.is/{ip}");
                let Ok(result) = client.get(url).send().await else {
                    return request_error_ip_result("Ipwho.is", "Unable to connect");
                };

                let mut result_without_time = parse_ipwho_is_resp(result).await;
                result_without_time.used_time = Some(time_start.elapsed());
                result_without_time
            });
            vec![handle.await.unwrap()]
        } else {
            // --- 检查本机IP ---
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // 强制使用IPv4进行API访问
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("Ipwho.is");
                };

                let url = "https://ipwho.is/";
                let Ok(result) = client_v4.get(url).send().await else {
                    return request_error_ip_result("Ipwho.is", "Unable to connect");
                };

                let mut result_without_time = parse_ipwho_is_resp(result).await;
                result_without_time.used_time = Some(time_start.elapsed());
                result_without_time
            });

            vec![handle_v4.await.unwrap()]
        }
    }
}

async fn parse_ipwho_is_resp(response: Response) -> IpResult {
    #[derive(Deserialize, Serialize)]
    struct Resp {
        success: bool,
        message: Option<String>,
        ip: Option<IpAddr>,
        country: Option<String>,
        region: Option<String>,
        city: Option<String>,
        latitude: Option<f64>,
        longitude: Option<f64>,
        connection: Option<ConnectionData>,
        timezone: Option<TimezoneData>,
    }
    #[derive(Deserialize, Serialize)]
    struct ConnectionData {
        asn: Option<u32>,
        isp: Option<String>,
    }
    #[derive(Deserialize, Serialize)]
    struct TimezoneData {
        id: Option<String>,
    }

    let Ok(json) = response.json::<Resp>().await else {
        return json_parse_error_ip_result("Ipwho.is", "Unable to parse result into Json");
    };

    if !json.success {
        let err_msg = json
            .message
            .unwrap_or_else(|| "API returned success=false".to_string());
        return request_error_ip_result("Ipwho.is", &err_msg);
    }

    if json.ip.is_none() {
        return request_error_ip_result("Ipwho.is", "API response did not contain an IP address.");
    }

    let connection = json.connection.as_ref();
    let asn_num = connection.and_then(|c| c.asn);
    let isp_name = connection.and_then(|c| c.isp.clone());

    IpResult {
        success: true,
        error: No,
        provider: "Ipwho.is".to_string(),
        ip: json.ip,
        autonomous_system: {
            if let (Some(number), Some(name)) = (asn_num, isp_name) {
                Some(AS { number, name })
            } else {
                None
            }
        },
        region: Some(Region {
            country: json.country,
            region: json.region,
            city: json.city,
            coordinates: if let (Some(lat), Some(lon)) = (json.latitude, json.longitude) {
                Some(Coordinates {
                    lat: lat.to_string(),
                    lon: lon.to_string(),
                })
            } else {
                None
            },
            time_zone: json.timezone.and_then(|tz| tz.id),
        }),
        risk: None, // API不提供风险信息
        used_time: None,
    }
}
