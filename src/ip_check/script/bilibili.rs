use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, request_error_ip_result, Coordinates, IpResult,
    Region,
};
use crate::ip_check::script::create_reqwest_client;
use crate::ip_check::IpCheck;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct Bilibili;

#[async_trait]
impl IpCheck for Bilibili {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("Bilibili");
                };

                let Ok(result) = client
                    .get(format!(
                        "https://api.live.bilibili.com/ip_service/v1/ip_service/get_ip_addr?ip={ip}"
                    ))
                    .send()
                    .await
                else {
                    return request_error_ip_result("Bilibili", "Unable to connect");
                };

                let mut result_without_time = parse_bilibili(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });
            let mut results = Vec::new();
            if let Ok(result) = handle.await {
                results.push(result);
            }
            results
        } else {
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("Bilibili");
                };

                let Ok(result) = client_v4
                    .get("https://api.live.bilibili.com/ip_service/v1/ip_service/get_ip_addr")
                    .send()
                    .await
                else {
                    return request_error_ip_result("Bilibili", "Unable to connect");
                };

                let mut result_without_time = parse_bilibili(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });
            let mut results = Vec::new();
            if let Ok(result) = handle_v4.await {
                results.push(result);
            }
            results
        }
    }
}

async fn parse_bilibili(response: Response) -> IpResult {
    #[derive(Deserialize, Serialize)]
    struct BilibiliResp {
        data: Data,
    }
    #[derive(Deserialize, Serialize)]
    struct Data {
        addr: IpAddr,
        country: Option<String>,
        province: Option<String>,
        city: Option<String>,
        isp: Option<String>,
        latitude: Option<String>,
        longitude: Option<String>,
    }

    let Ok(json) = response.json::<BilibiliResp>().await else {
        return json_parse_error_ip_result(
            "Bilibili",
            "Unable to parse the returned result into Json",
        );
    };

    IpResult {
        success: true,
        error: No,
        provider: "Bilibili".to_string(),
        ip: Some(json.data.addr),
        autonomous_system: None,
        region: Some(Region {
            country: json.data.country,
            region: json.data.province,
            city: json.data.city,
            coordinates: if let (Some(lat), Some(lon)) = (json.data.latitude, json.data.longitude) {
                Some(Coordinates { lat, lon })
            } else {
                None
            },
            time_zone: None,
        }),
        risk: None,
        used_time: None,
    }
}
