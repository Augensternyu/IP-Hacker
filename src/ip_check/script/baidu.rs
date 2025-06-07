use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{create_reqwest_client_error, json_parse_error_ip_result, request_error_ip_result, IpResult, Region, AS};
use crate::ip_check::script::create_reqwest_client;
use crate::ip_check::IpCheck;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct Baidu;

#[async_trait]
impl IpCheck for Baidu {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            let handle = tokio::spawn(async move {
                let Ok(client) = create_reqwest_client(None, None).await else {
                    return create_reqwest_client_error("Baidu");
                };

                let Ok(result) = client
                    .get(format!("https://qifu-api.baidubce.com/ip/geo/v1/district?ip={ip}"))
                    .send()
                    .await
                else {
                    return request_error_ip_result("Baidu", "Unable to connect");
                };

                parse_baidu_resp(result).await
            });

            let mut results = Vec::new();
            if let Ok(result) = handle.await {
                results.push(result);
            }
            results
        } else {
            let handle_v4 = tokio::spawn(async move {
                let Ok(client_v4) = create_reqwest_client(None, Some(false)).await else {
                    return create_reqwest_client_error("Baidu");
                };

                let Ok(result) = client_v4
                    .get("https://qifu-api.baidubce.com/ip/local/geo/v1/district")
                    .send()
                    .await
                else {
                    return request_error_ip_result("Baidu", "Unable to connect");
                };

                parse_baidu_resp(result).await
            });

            let mut results = Vec::new();
            if let Ok(result) = handle_v4.await {
                results.push(result);
            }
            results
        }
    }
}

async fn parse_baidu_resp(response: Response) -> IpResult {
    #[derive(Deserialize, Serialize)]
    struct BaiduResp {
        code: String,
        data: Data,
        ip: Option<IpAddr>
    }
    #[derive(Deserialize, Serialize)]
    struct Data {
        country: Option<String>,
        isp: Option<String>,
        prov: Option<String>,
        city: Option<String>,
    }

    let Ok(json) = response.json::<BaiduResp>().await else {
        return json_parse_error_ip_result(
            "Baidu",
            "Unable to parse the returned result into Json",
        );
    };

    if json.code != *"Success" {
        return json_parse_error_ip_result("Baidu", "Server returned an error");
    }

    IpResult {
        success: true,
        error: No,
        provider: "Baidu".to_string(),
        ip: json.ip,
        autonomous_system: {
            json.data.isp.map(|isp| AS {
                    number: 0,
                    name: isp,
                })
        },
        region: Some(Region {
            country: json.data.country,
            region: json.data.prov,
            city: json.data.city,
            coordinates: None,
            time_zone: None,
        }),
        risk: None,
    }
}
