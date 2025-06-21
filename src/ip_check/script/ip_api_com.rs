use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::RiskTag::{Mobile, Proxy};
use crate::ip_check::ip_result::{
    AS, Coordinates, IpResult, Region, Risk, create_reqwest_client_error,
    json_parse_error_ip_result, request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct IpApiCom;

#[async_trait]
impl IpCheck for IpApiCom {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();

                let Ok(client) = create_reqwest_client(None).await else {
                    return create_reqwest_client_error("Ip-Api.com");
                };

                let Ok(result) = client
                    .get(format!("https://pro.ip-api.com/json/{ip}?fields=66846719&key=EEKS6bLi6D91G1p&lang=en-US"))
                    .send()
                    .await
                else {
                    return request_error_ip_result("Ip-Api.com", "Unable to connect");
                };

                let mut result_without_time = get_ip_api_com_info(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            vec![handle.await.unwrap_or(json_parse_error_ip_result(
                "Ip-Api.com",
                "Unable to parse json",
            ))]
        } else {
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();

                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("Ip-Api.com");
                };

                let Ok(result) = client_v4
                    .get("https://pro.ip-api.com/json/?fields=66846719&key=EEKS6bLi6D91G1p")
                    .send()
                    .await
                else {
                    return request_error_ip_result("Ip-Api.com", "Unable to connect");
                };

                let mut result_without_time = get_ip_api_com_info(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            vec![handle_v4.await.unwrap_or(json_parse_error_ip_result(
                "Ip-Api.com",
                "Unable to parse json",
            ))]
        }
    }
}

async fn get_ip_api_com_info(resp: Response) -> IpResult {
    #[derive(Deserialize, Serialize)]
    struct IpApiComResp {
        status: String,
        country: Option<String>,

        #[serde(rename = "regionName")]
        region_name: Option<String>,

        city: Option<String>,
        lat: Option<f64>,
        lon: Option<f64>,
        timezone: Option<String>,
        isp: Option<String>,

        #[serde(rename = "as")]
        asn: Option<String>,

        #[serde(rename = "query")]
        ip: Option<IpAddr>,

        proxy: bool,
        hosting: bool,
        mobile: bool,
    }

    let Ok(json) = resp.json::<IpApiComResp>().await else {
        return json_parse_error_ip_result(
            "Ip-Api.com",
            "Unable to parse the returned result into Json",
        );
    };

    if json.status != "success" {
        return request_error_ip_result("Ip-Api.com", "Unable to get Ip API info");
    }

    let asn = if let Some(asn) = json.asn {
        let asn = asn.split(' ').collect::<Vec<&str>>()[0];
        Some(asn.replace("AS", "").parse::<u32>().unwrap_or(0))
    } else {
        None
    };

    IpResult {
        success: true,
        error: No,
        provider: "Ip-Api.com".to_string(),
        ip: json.ip,
        autonomous_system: {
            if let (Some(asn), Some(isp)) = (asn, json.isp) {
                Some(AS {
                    number: asn,
                    name: isp,
                })
            } else {
                None
            }
        },
        region: Some(Region {
            country: json.country,
            region: json.region_name,
            city: json.city,
            coordinates: {
                if let (Some(lat), Some(lon)) = (json.lat, json.lon) {
                    Some(Coordinates {
                        lat: lat.to_string(),
                        lon: lon.to_string(),
                    })
                } else {
                    None
                }
            },
            time_zone: json.timezone,
        }),
        risk: {
            let mut tags = vec![];
            if json.proxy {
                tags.push(Proxy);
            }
            if json.mobile {
                tags.push(Mobile);
            }
            if json.hosting {
                tags.push(Mobile);
            }
            Some(Risk {
                risk: None,
                tags: Some(tags),
            })
        },
        used_time: None,
    }
}
