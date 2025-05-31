use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    AS, Coordinates, IpResult, Region, create_reqwest_client_error, parse_ip_error_ip_result,
    request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct IPApiCo;

#[async_trait]
impl IpCheck for IPApiCo {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            let handle = tokio::spawn(async move {
                let Ok(client_v4) = create_reqwest_client(Some("curl/8.11.0"), None).await else {
                    return create_reqwest_client_error("IpApi.co");
                };

                let Ok(result) = client_v4
                    .get(format!("https://ipapi.co/{ip}/json"))
                    .send()
                    .await
                else {
                    return request_error_ip_result("IpApi.co", "Unable to connect to api.myip.la");
                };
                parse_ipapi_co_info(result).await
            });
            vec![handle.await.unwrap_or(parse_ip_error_ip_result(
                "IpApi.co",
                "Unable to parse IpApi.co",
            ))]
        } else {
            let handle_v4 = tokio::spawn(async move {
                let Ok(client_v4) = create_reqwest_client(Some("curl/8.11.0"), Some(false)).await
                else {
                    return create_reqwest_client_error("IpApi.co");
                };

                let Ok(result) = client_v4.get("https://ipapi.co/json").send().await else {
                    return request_error_ip_result("IpApi.co", "Unable to connect to api.myip.la");
                };

                parse_ipapi_co_info(result).await
            });

            let handle_v6 = tokio::spawn(async move {
                let Ok(client_v6) = create_reqwest_client(Some("curl/8.11.0"), Some(true)).await
                else {
                    return create_reqwest_client_error("IpApi.co");
                };

                let Ok(result) = client_v6.get("https://ipapi.co/json").send().await else {
                    return request_error_ip_result("IpApi.co", "Unable to connect to api.myip.la");
                };

                parse_ipapi_co_info(result).await
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

async fn parse_ipapi_co_info(response: Response) -> IpResult {
    #[derive(Deserialize, Serialize, Debug)]
    struct IPApiCoResp {
        ip: Option<IpAddr>,
        city: Option<String>,
        region: Option<String>,
        country_name: Option<String>,
        latitude: Option<f64>,
        longitude: Option<f64>,
        timezone: Option<String>,
        asn: Option<String>,
        org: Option<String>,
    }

    let Ok(json) = response.json::<IPApiCoResp>().await else {
        return request_error_ip_result("IpApi.co", "Unable to parse MyIPLa Json");
    };

    let asn = json
        .asn
        .map(|asn| asn.replace("AS", "").trim().parse::<u32>().unwrap_or(0));

    IpResult {
        success: true,
        error: No,
        provider: "IpApi.co".to_string(),
        ip: json.ip,
        autonomous_system: {
            if let (Some(asn), Some(isp)) = (asn, json.org) {
                Some(AS {
                    number: asn,
                    name: isp,
                })
            } else {
                None
            }
        },
        region: Some(Region {
            country: json.country_name,
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
            time_zone: json.timezone,
        }),
        risk: None,
    }
}
