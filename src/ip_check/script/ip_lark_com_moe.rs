use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, not_support_error, request_error_ip_result, Coordinates,
    IpResult, Region,
};
use crate::ip_check::script::create_reqwest_client;
use crate::ip_check::IpCheck;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct IpLarkComMoe;

#[async_trait]
impl IpCheck for IpLarkComMoe {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            vec![not_support_error("IpLark.com Moe")]
        } else {
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("IpLark.com Moe");
                };

                let Ok(result) = client_v4
                    .get("https://iplark.com/ipapi/public/ipinfo?db=moe")
                    .send()
                    .await
                else {
                    return request_error_ip_result("IpLark.com Moe", "Unable to connect");
                };

                let mut result_without_time = parse_ip_lark_com_moe(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error("IpLark.com Moe");
                };

                let Ok(result) = client_v6
                    .get("https://6.iplark.com/ipapi/public/ipinfo?db=moe")
                    .send()
                    .await
                else {
                    return request_error_ip_result("IpLark.com Moe", "Unable to connect");
                };

                let mut result_without_time = parse_ip_lark_com_moe(result).await;
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

async fn parse_ip_lark_com_moe(response: Response) -> IpResult {
    #[derive(Deserialize, Serialize)]
    struct IpLarkComMoeResp {
        ip: IpAddr,
        city_name: Option<String>,
        country_name: Option<String>,
        latitude: Option<f64>,
        longitude: Option<f64>,
        region_name: Option<String>,
        timezone: Option<String>,
    }

    let Ok(json) = response.json::<IpLarkComMoeResp>().await else {
        return json_parse_error_ip_result(
            "IpLark.com Moe",
            "Unable to parse the returned result into Json",
        );
    };

    IpResult {
        success: true,
        error: No,
        provider: "IpLark.com Moe".to_string(),
        ip: Some(json.ip),
        autonomous_system: None,
        region: Some(Region {
            country: json.country_name,
            region: json.region_name,
            city: json.city_name,
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
        used_time: None,
    }
}
