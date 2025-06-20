use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    Coordinates, IpResult, Region, create_reqwest_client_error, not_support_error,
    request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct MyIPLa;

#[async_trait]
impl IpCheck for MyIPLa {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            vec![not_support_error("Myip.La")]
        } else {
            let handle_v4 = tokio::spawn(async move {
                let Ok(client_v4) = create_reqwest_client(None, Some(false)).await else {
                    return create_reqwest_client_error("Myip.La");
                };

                let Ok(result) = client_v4.get("https://api.myip.la/en?json").send().await else {
                    return request_error_ip_result("Myip.La", "Unable to connect");
                };

                parse_myip_la_info(result).await
            });

            let handle_v6 = tokio::spawn(async move {
                let Ok(client_v6) = create_reqwest_client(None, Some(true)).await else {
                    return create_reqwest_client_error("Myip.La");
                };

                let Ok(result) = client_v6.get("https://api.myip.la/en?json").send().await else {
                    return request_error_ip_result("Myip.La", "Unable to connect");
                };

                parse_myip_la_info(result).await
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

async fn parse_myip_la_info(response: Response) -> IpResult {
    #[derive(Deserialize, Serialize)]
    struct MyIPLaResp {
        ip: Option<IpAddr>,
        location: Location,
    }
    #[derive(Deserialize, Serialize)]
    struct Location {
        city: Option<String>,
        country_name: Option<String>,
        province: Option<String>,
        latitude: Option<String>,
        longitude: Option<String>,
    }

    let Ok(json) = response.json::<MyIPLaResp>().await else {
        return request_error_ip_result("MyIP.La", "Unable to parse Json");
    };

    IpResult {
        success: true,
        error: No,
        provider: "MyIP.La".to_string(),
        ip: json.ip,
        autonomous_system: None,
        region: Some(Region {
            country: json.location.country_name,
            region: json.location.province,
            city: json.location.city,
            coordinates: if let (Some(lat), Some(lon)) =
                (json.location.latitude, json.location.longitude)
            {
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
