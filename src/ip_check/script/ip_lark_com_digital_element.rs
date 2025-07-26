use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::RiskTag::{Hosting, Mobile, Other, Proxy, Tor};
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, not_support_error, request_error_ip_result, Coordinates, IpResult,
    Region, Risk, AS,
};
use crate::ip_check::script::create_reqwest_client;
use crate::ip_check::IpCheck;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;

pub struct IpLarkComDigitalElement;

#[async_trait]
impl IpCheck for IpLarkComDigitalElement {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            vec![not_support_error("IpLark.com Digital Element")]
        } else {
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("IpLark.com Digital Element");
                };

                let Ok(result) = client_v4
                    .get("https://iplark.com/ipapi/public/ipinfo?db=digital")
                    .send()
                    .await
                else {
                    return request_error_ip_result(
                        "IpLark.com Digital Element",
                        "Unable to connect",
                    );
                };

                let mut result_without_time = parse_ip_lark_com_digital_element(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error("IpLark.com Digital Element");
                };

                let Ok(result) = client_v6
                    .get("https://6.iplark.com/ipapi/public/ipinfo?db=digital")
                    .send()
                    .await
                else {
                    return request_error_ip_result(
                        "IpLark.com Digital Element",
                        "Unable to connect",
                    );
                };

                let mut result_without_time = parse_ip_lark_com_digital_element(result).await;
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

async fn parse_ip_lark_com_digital_element(response: Response) -> IpResult {
    #[derive(Deserialize, Serialize)]
    struct IpLarkComDigitalElementResp {
        ip: IpAddr,
        country: Option<String>,
        // region: Option<String>,
        city: Option<String>,
        latitude: Option<f64>,
        longitude: Option<f64>,
        asn: Option<u32>,
        asname: Option<String>,
        connection: Option<String>,
        connection_type: Option<String>,

        #[serde(rename = "type")]
        type_str: Option<String>,
        tag: Option<String>,
    }

    let Ok(json) = response.json::<IpLarkComDigitalElementResp>().await else {
        return json_parse_error_ip_result(
            "IpLark.com Digital Element",
            "Unable to parse the returned result into Json",
        );
    };

    let mut tags = Vec::new();
    if let Some(connection) = json.connection {
        match connection.as_str() {
            "mobile" => tags.push(Mobile),
            _ => tags.push(Other(connection.to_uppercase())),
        }
    }

    if let Some(connection_type) = json.connection_type {
        match connection_type.as_str() {
            "mobile" => tags.push(Mobile),
            _ => tags.push(Other(connection_type.to_uppercase())),
        }
    }

    if let Some(type_str) = json.type_str {
        match type_str.as_str() {
            "hosting" => tags.push(Hosting),
            _ => tags.push(Other(type_str.to_uppercase())),
        }
    }

    if let Some(tag) = json.tag {
        match tag.as_str() {
            "tor-exit" => tags.push(Tor),
            "vpn" => tags.push(Proxy),
            _ => tags.push(Other(tag.to_uppercase())),
        }
    }

    let mut seen = HashSet::new();
    let mut result = Vec::new();

    for tag in tags {
        seen.insert(tag.clone());
    }

    for tag in seen {
        result.push(tag);
    }

    IpResult {
        success: true,
        error: No,
        provider: "IpLark.com Digital Element".to_string(),
        ip: Some(json.ip),
        autonomous_system: {
            if let (Some(asn), Some(isp)) = (json.asn, json.asname) {
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
            region: None,
            city: json.city,
            coordinates: if let (Some(lat), Some(lon)) = (json.latitude, json.longitude) {
                Some(Coordinates {
                    lat: lat.to_string(),
                    lon: lon.to_string(),
                })
            } else {
                None
            },
            time_zone: None,
        }),
        risk: Some(Risk {
            risk: None,
            tags: Some(result),
        }),
        used_time: None,
    }
}
