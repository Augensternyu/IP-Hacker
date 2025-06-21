use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::RiskTag::{Hosting, Other, Proxy, Tor};
use crate::ip_check::ip_result::{
    AS, Coordinates, IpResult, Region, Risk, create_reqwest_client_error,
    json_parse_error_ip_result, not_support_error, request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct IpLarkComIpStack;

#[async_trait]
impl IpCheck for IpLarkComIpStack {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            vec![not_support_error("IpLark.com IpStack")]
        } else {
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("IpLark.com IpStack");
                };

                let Ok(result) = client_v4
                    .get("https://iplark.com/ipapi/public/ipinfo?db=ipstack")
                    .send()
                    .await
                else {
                    return request_error_ip_result("IpLark.com IpStack", "Unable to connect");
                };

                let mut result_without_time = parse_ip_lark_com_ip_stack(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error("IpLark.com IpStack");
                };

                let Ok(result) = client_v6
                    .get("https://6.iplark.com/ipapi/public/ipinfo?db=ipstack")
                    .send()
                    .await
                else {
                    return request_error_ip_result("IpLark.com IpStack", "Unable to connect");
                };

                let mut result_without_time = parse_ip_lark_com_ip_stack(result).await;
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

async fn parse_ip_lark_com_ip_stack(response: Response) -> IpResult {
    #[derive(Deserialize, Serialize)]
    struct IpLarkComIpStackResp {
        ip: IpAddr,
        region_name: Option<String>,
        city: Option<String>,
        latitude: Option<f64>,
        longitude: Option<f64>,
        country_name: Option<String>,
        time_zone: TimeZone,
        connection: Connection,
        security: Security,
    }
    #[derive(Deserialize, Serialize)]
    struct TimeZone {
        time_zone: Option<String>,
    }
    #[derive(Deserialize, Serialize)]
    struct Connection {
        asn: Option<u32>,
        isp: Option<String>,
    }
    #[derive(Deserialize, Serialize)]
    struct Security {
        is_proxy: Option<bool>,
        is_crawler: Option<bool>,
        is_tor: Option<bool>,
        hosting_facility: Option<bool>,
    }

    let Ok(json) = response.json::<IpLarkComIpStackResp>().await else {
        return json_parse_error_ip_result(
            "IpLark.com IpStack",
            "Unable to parse the returned result into Json",
        );
    };

    let mut tags = Vec::new();

    if json.security.is_proxy.unwrap_or(false) {
        tags.push(Proxy);
    }
    if json.security.is_crawler.unwrap_or(false) {
        tags.push(Other("CRAWLER".to_string()));
    }
    if json.security.is_tor.unwrap_or(false) {
        tags.push(Tor);
    }
    if json.security.hosting_facility.unwrap_or(false) {
        tags.push(Hosting);
    }

    IpResult {
        success: true,
        error: No,
        provider: "IpLark.com IpStack".to_string(),
        ip: Some(json.ip),
        autonomous_system: {
            if let (Some(asn), Some(isp)) = (json.connection.asn, json.connection.isp) {
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
            region: json.region_name,
            city: json.city,
            coordinates: if let (Some(lat), Some(lon)) = (json.latitude, json.longitude) {
                Some(Coordinates {
                    lat: lat.to_string(),
                    lon: lon.to_string(),
                })
            } else {
                None
            },
            time_zone: json.time_zone.time_zone,
        }),
        risk: Some(Risk {
            risk: None,
            tags: Some(tags),
        }),
        used_time: None,
    }
}
