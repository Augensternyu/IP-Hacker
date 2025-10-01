use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::RiskTag::Proxy;
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, request_error_ip_result, Coordinates, IpResult, Region,
    Risk, AS,
};
use crate::ip_check::script::create_reqwest_client;
use crate::ip_check::IpCheck;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct Ip2locationIo;

// 定义API密钥和User-Agent为常量
const API_KEY: &str = "2AB0410E3D2DC3AD167C13D08309F394";

#[async_trait]
impl IpCheck for Ip2locationIo {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            // --- 检查指定IP ---
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client) = create_reqwest_client(None).await else {
                    return create_reqwest_client_error("Ip2location.io");
                };

                let url = format!("https://api.ip2location.io/?ip={ip}&key={API_KEY}");
                let Ok(result) = client.get(url).send().await else {
                    return request_error_ip_result("Ip2location.io", "Unable to connect");
                };

                let mut result_without_time = parse_ip2location_io_resp(result).await;
                result_without_time.used_time = Some(time_start.elapsed());
                result_without_time
            });
            vec![handle.await.unwrap()]
        } else {
            // --- 检查本机IP (IPv4 和 IPv6) ---
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("Ip2location.io");
                };

                let url = format!("https://api.ip2location.io/?key={API_KEY}");
                let Ok(result) = client_v4.get(url).send().await else {
                    return request_error_ip_result("Ip2location.io", "Unable to connect (v4)");
                };

                let mut result_without_time = parse_ip2location_io_resp(result).await;
                result_without_time.used_time = Some(time_start.elapsed());
                result_without_time
            });

            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error("Ip2location.io");
                };

                let url = format!("https://api.ip2location.io/?key={API_KEY}");
                let Ok(result) = client_v6.get(url).send().await else {
                    return request_error_ip_result("Ip2location.io", "Unable to connect (v6)");
                };

                let mut result_without_time = parse_ip2location_io_resp(result).await;
                result_without_time.used_time = Some(time_start.elapsed());
                result_without_time
            });

            let mut results = Vec::new();
            if let Ok(result) = handle_v4.await
                && result.success {
                    results.push(result);
                }
            if let Ok(result) = handle_v6.await
                && result.success {
                    results.push(result);
                }
            results
        }
    }
}

async fn parse_ip2location_io_resp(response: Response) -> IpResult {
    #[derive(Deserialize, Serialize)]
    struct Resp {
        ip: Option<IpAddr>,
        country_name: Option<String>,
        region_name: Option<String>,
        city_name: Option<String>,
        latitude: Option<f64>,
        longitude: Option<f64>,
        asn: Option<String>,
        #[serde(rename = "as")]
        as_name: Option<String>,
        is_proxy: Option<bool>,
        error: Option<ErrorData>, // 用于捕获API自身的错误信息
    }
    #[derive(Deserialize, Serialize)]
    struct ErrorData {
        error_message: String,
    }

    let Ok(json) = response.json::<Resp>().await else {
        return json_parse_error_ip_result("Ip2location.io", "Unable to parse result into Json");
    };

    if let Some(error_data) = json.error {
        return request_error_ip_result("Ip2location.io", &error_data.error_message);
    }

    // 如果没有IP地址，说明是一个失败的请求
    if json.ip.is_none() {
        return request_error_ip_result(
            "Ip2location.io",
            "API response did not contain an IP address.",
        );
    }

    let asn_num = json
        .asn
        .map_or(0, |asn_str| asn_str.parse::<u32>().unwrap_or(0));

    let mut risk_tags = Vec::new();
    if json.is_proxy.unwrap_or(false) {
        risk_tags.push(Proxy);
    }

    IpResult {
        success: true,
        error: No,
        provider: "Ip2location.io".to_string(),
        ip: json.ip,
        autonomous_system: {
            json.as_name.map(|isp| AS {
                number: asn_num,
                name: isp,
            })
        },
        region: Some(Region {
            country: json.country_name,
            province: json.region_name,
            city: json.city_name,
            coordinates: if let (Some(latitude), Some(longitude)) = (json.latitude, json.longitude) {
                Some(Coordinates {
                    latitude: latitude.to_string(),
                    longitude: longitude.to_string(),
                })
            } else {
                None
            },
            time_zone: None,
        }),
        risk: Some(Risk {
            risk: None, // API不提供风险分数，只提供标签
            tags: Some(risk_tags),
        }),
        used_time: None,
    }
}
