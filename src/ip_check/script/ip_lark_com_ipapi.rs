use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::RiskTag::{Hosting, Mobile, Proxy};
use crate::ip_check::ip_result::{
    AS, Coordinates, IpResult, Region, Risk, create_reqwest_client_error,
    json_parse_error_ip_result, not_support_error, request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct IpLarkComIpApi;

#[async_trait]
impl IpCheck for IpLarkComIpApi {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            vec![not_support_error("IpLark.com IpApi")]
        } else {
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("IpLark.com IpApi");
                };

                let Ok(result) = client_v4
                    .get("https://iplark.com/ipapi/public/ipinfo?db=ipapi")
                    .send()
                    .await
                else {
                    return request_error_ip_result("IpLark.com IpApi", "Unable to connect");
                };

                let mut result_without_time = parse_ip_lark_com_ipapi(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error("IpLark.com IpApi");
                };

                let Ok(result) = client_v6
                    .get("https://6.iplark.com/ipapi/public/ipinfo?db=ipapi")
                    .send()
                    .await
                else {
                    return request_error_ip_result("IpLark.com IpApi", "Unable to connect");
                };

                let mut result_without_time = parse_ip_lark_com_ipapi(result).await;
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

async fn parse_ip_lark_com_ipapi(response: Response) -> IpResult {
    #[derive(Deserialize, Serialize)]
    struct IpLarkComIpApiResp {
        #[serde(rename = "as")]
        asn: Option<String>,
        city: Option<String>,
        country: Option<String>,

        #[serde(rename = "regionName")]
        region_name: Option<String>,

        timezone: Option<String>,
        query: IpAddr,
        isp: Option<String>,
        lat: Option<f64>,
        lon: Option<f64>,

        hosting: Option<bool>,
        proxy: Option<bool>,
        mobile: Option<bool>,
    }

    let Ok(json) = response.json::<IpLarkComIpApiResp>().await else {
        return json_parse_error_ip_result(
            "IpLark.com IpApi",
            "Unable to parse the returned result into Json",
        );
    };

    let mut risk_tags = Vec::new();
    if let Some(true) = json.hosting {
        risk_tags.push(Hosting);
    }
    if let Some(true) = json.proxy {
        risk_tags.push(Proxy);
    }
    if let Some(true) = json.mobile {
        risk_tags.push(Mobile);
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
        provider: "IpLark.com IpApi".to_string(),
        ip: Some(json.query),
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
            coordinates: if let (Some(lat), Some(lon)) = (json.lat, json.lon) {
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
            tags: Some(risk_tags),
        }),
        used_time: None,
    }
}
