use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::RiskTag::{Hosting, Other};
use crate::ip_check::ip_result::{
    AS, Coordinates, IpResult, Region, Risk, create_reqwest_client_error,
    json_parse_error_ip_result, not_support_error, request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct IpLarkComMaxmind;

#[async_trait]
impl IpCheck for IpLarkComMaxmind {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            vec![not_support_error("IpLark.com Maxmind")]
        } else {
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();

                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("IpLark.com Maxmind");
                };

                let Ok(result) = client_v4
                    .get("https://iplark.com/ipapi/public/ipinfo")
                    .send()
                    .await
                else {
                    return request_error_ip_result("IpLark.com Maxmind", "Unable to connect");
                };

                let mut result_without_time = parse_ip_lark_com_maxmind(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error("IpLark.com Maxmind");
                };

                let Ok(result) = client_v6
                    .get("https://6.iplark.com/ipapi/public/ipinfo")
                    .send()
                    .await
                else {
                    return request_error_ip_result("IpLark.com Maxmind", "Unable to connect");
                };

                let mut result_without_time = parse_ip_lark_com_maxmind(result).await;
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

async fn parse_ip_lark_com_maxmind(response: Response) -> IpResult {
    #[derive(Deserialize, Serialize)]
    struct IpLarkComMaxmindResp {
        ip: IpAddr,
        country: Option<String>,
        region: Option<String>,
        city: Option<String>,
        latitude: Option<f64>,
        longitude: Option<f64>,
        asn: Option<u32>,
        organization: Option<String>,

        #[serde(rename = "type")]
        type_str: Option<String>,
        timezone: Option<String>,
    }

    let Ok(json) = response.json::<IpLarkComMaxmindResp>().await else {
        return json_parse_error_ip_result(
            "IpLark.com Maxmind",
            "Unable to parse the returned result into Json",
        );
    };

    let mut tags = Vec::new();
    if let Some(type_str) = json.type_str {
        match type_str.as_str() {
            "hosting" => tags.push(Hosting),
            _ => tags.push(Other(type_str)),
        }
    }

    IpResult {
        success: true,
        error: No,
        provider: "IpLark.com Maxmind".to_string(),
        ip: Some(json.ip),
        autonomous_system: {
            if let (Some(asn), Some(isp)) = (json.asn, json.organization) {
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
        risk: Some(Risk {
            risk: None,
            tags: Some(tags),
        }),
        used_time: None,
    }
}
