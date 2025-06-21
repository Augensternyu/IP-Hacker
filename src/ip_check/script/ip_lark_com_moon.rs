use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, not_support_error, request_error_ip_result,
    Coordinates, IpResult, Region,
};
use crate::ip_check::script::create_reqwest_client;
use crate::ip_check::IpCheck;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct IpLarkComMoon;

#[async_trait]
impl IpCheck for IpLarkComMoon {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            vec![not_support_error("IpLark.com Moon")]
        } else {
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v4) = create_reqwest_client(None, Some(false)).await else {
                    return create_reqwest_client_error("IpLark.com Moon");
                };

                let Ok(result) = client_v4
                    .get("https://iplark.com/ipapi/public/ipinfo?db=moon")
                    .send()
                    .await
                else {
                    return request_error_ip_result(
                        "IpLark.com Moon",
                        "Unable to connect",
                    );
                };

                let mut result_without_time = parse_ip_lark_com_moon(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v6) = create_reqwest_client(None, Some(true)).await else {
                    return create_reqwest_client_error("IpLark.com Moon");
                };

                let Ok(result) = client_v6
                    .get("https://6.iplark.com/ipapi/public/ipinfo?db=moon")
                    .send()
                    .await
                else {
                    return request_error_ip_result(
                        "IpLark.com Moon",
                        "Unable to connect",
                    );
                };

                let mut result_without_time = parse_ip_lark_com_moon(result).await;
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

async fn parse_ip_lark_com_moon(response: Response) -> IpResult {
    #[derive(Deserialize, Serialize)]
    struct IpLarkComMoonResp {
        data: Data,
    }
    #[derive(Deserialize, Serialize)]
    struct Data {
        ip: IpAddr,
        country: Option<String>,
        province: Option<String>,
        city: Option<String>,
        latitude: Option<f64>,
        longitude: Option<f64>,
    }

    let Ok(json) = response.json::<IpLarkComMoonResp>().await else {
        return json_parse_error_ip_result(
            "IpLark.com Moon",
            "Unable to parse the returned result into Json",
        );
    };

    IpResult {
        success: true,
        error: No,
        provider: "IpLark.com Moon".to_string(),
        ip: Some(json.data.ip),
        autonomous_system: None,
        region:  Some(Region {
            country: json.data.country,
            region: json.data.province,
            city: json.data.city,
            coordinates: if let (Some(lat), Some(lon)) = (json.data.latitude, json.data.longitude) {
                Some(Coordinates {
                    lat: lat.to_string(),
                    lon: lon.to_string(),
                })
            } else {
                None
            },
            time_zone: None,
        }),
        risk: None,
        used_time: None,
    }
}
