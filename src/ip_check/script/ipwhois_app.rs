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

pub struct IpWhoisApp;

#[async_trait]
impl IpCheck for IpWhoisApp {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            let handle = tokio::spawn(async move {
                let Ok(client) = create_reqwest_client(None, None).await else {
                    return create_reqwest_client_error("IpWhois.app");
                };

                let Ok(result) = client
                    .get(format!("https://ipwhois.app/json/{ip}?format=json"))
                    .send()
                    .await
                else {
                    return request_error_ip_result("IpWhois.app", "Unable to connect");
                };

                parse_ipwhois_app_resp(result).await
            });
            vec![handle.await.unwrap_or(json_parse_error_ip_result(
                "IpWhois.app",
                "Unable to parse json",
            ))]
        } else {
            let handle_v4 = tokio::spawn(async move {
                let Ok(client_v4) = create_reqwest_client(None, Some(false)).await else {
                    return create_reqwest_client_error("IpWhois.app");
                };

                let Ok(result) = client_v4
                    .get("https://ipwhois.app/json/?format=json")
                    .send()
                    .await
                else {
                    return request_error_ip_result("IpWhois.app", "Unable to connect");
                };

                parse_ipwhois_app_resp(result).await
            });

            let mut results = Vec::new();
            if let Ok(result) = handle_v4.await {
                results.push(result);
            }
            results
        }
    }
}

async fn parse_ipwhois_app_resp(response: Response) -> IpResult {
    #[derive(Deserialize, Serialize)]
    struct IpWhoisAppResp {
        ip: Option<IpAddr>,
        success: bool,
        country: Option<String>,
        region: Option<String>,
        city: Option<String>,
        latitude: Option<f64>,
        longitude: Option<f64>,
        asn: Option<String>,
        isp: Option<String>,
        timezone: Option<String>,
    }

    let Ok(json) = response.json::<IpWhoisAppResp>().await else {
        return json_parse_error_ip_result(
            "IpWhois.app",
            "Unable to parse the returned result into Json",
        );
    };

    if !json.success {
        return json_parse_error_ip_result("IpWhois.app", "Server returned an error");
    }

    IpResult {
        success: true,
        error: No,
        provider: "IpWhois.app".to_string(),
        ip: json.ip,
        autonomous_system: {
            if let (Some(asn), Some(isp)) = (json.asn, json.isp) {
                Some(AS {
                    number: asn.replace("AS", "").parse::<u32>().unwrap_or(0),
                    name: isp,
                })
            } else {
                None
            }
        },
        region: Some(Region {
            country: json.country,
            region: json.region,
            city: json.city,
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
            time_zone: json.timezone,
        }),
        risk: None,
        used_time: None,
    }
}
