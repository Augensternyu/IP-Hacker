use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::RiskTag::Proxy;
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, request_error_ip_result, Coordinates, IpResult, Region,
    Risk,
};
use crate::ip_check::script::create_reqwest_client;
use crate::ip_check::IpCheck;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct FreeIpApiCom;

#[async_trait]
impl IpCheck for FreeIpApiCom {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();

                let Ok(client) = create_reqwest_client(None).await else {
                    return create_reqwest_client_error("FreeIpApi.com");
                };

                let Ok(result) = client
                    .get(format!("https://freeipapi.com/api/json/{ip}"))
                    .send()
                    .await
                else {
                    return request_error_ip_result("FreeIpApi.com", "Unable to connect");
                };

                let mut result_without_time = parse_free_ip_api_com_resp(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });
            vec![handle.await.unwrap_or(json_parse_error_ip_result(
                "FreeIpApi.com",
                "Unable to parse json",
            ))]
        } else {
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();

                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("FreeIpApi.com");
                };

                let Ok(result) = client_v4.get("https://freeipapi.com/api/json").send().await
                else {
                    return request_error_ip_result("FreeIpApi.com", "Unable to connect");
                };

                let mut result_without_time = parse_free_ip_api_com_resp(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();

                let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error("FreeIpApi.com");
                };

                let Ok(result) = client_v6.get("https://freeipapi.com/api/json").send().await
                else {
                    return request_error_ip_result("FreeIpApi.com", "Unable to connect");
                };

                let mut result_without_time = parse_free_ip_api_com_resp(result).await;
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

async fn parse_free_ip_api_com_resp(response: Response) -> IpResult {
    #[derive(Deserialize, Serialize)]
    struct FreeIpApiComResp {
        #[serde(rename = "ipAddress")]
        ip: Option<IpAddr>,

        latitude: Option<f64>,
        longitude: Option<f64>,

        #[serde(rename = "countryName")]
        country_name: Option<String>,

        #[serde(rename = "cityName")]
        city_name: Option<String>,

        #[serde(rename = "regionName")]
        region_name: Option<String>,

        #[serde(rename = "isProxy")]
        is_proxy: Option<bool>,
    }

    let Ok(json) = response.json::<FreeIpApiComResp>().await else {
        return json_parse_error_ip_result(
            "FreeIpApi.com",
            "Unable to parse the returned result into Json",
        );
    };

    IpResult {
        success: true,
        error: No,
        provider: "FreeIpApi.com".to_string(),
        ip: json.ip,
        autonomous_system: None,
        region: Some(Region {
            country: json.country_name,
            region: json.region_name,
            city: json.city_name,
            coordinates: {
                if let (Some(lat), Some(lon)) = (json.latitude, json.longitude) {
                    Some(Coordinates {
                        lat: lat.to_string(),
                        lon: lon.to_string(),
                    })
                } else {
                    None
                }
            },
            time_zone: None,
        }),
        risk: Some(Risk {
            risk: None,
            tags: {
                if Some(true) == json.is_proxy {
                    Some(vec![Proxy])
                } else {
                    None
                }
            },
        }),
        used_time: None,
    }
}
