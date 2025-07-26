use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, parse_ip_error_ip_result, request_error_ip_result, Coordinates, IpResult,
    Region, AS,
};
use crate::ip_check::script::create_reqwest_client;
use crate::ip_check::IpCheck;
use async_trait::async_trait;
use reqwest::header;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;

pub struct Maxmind;

#[async_trait]
impl IpCheck for Maxmind {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            let mut ip_results = Vec::new();
            ip_results.push({
                let time_start = tokio::time::Instant::now();
                let mut result_without_time = get_maxmind_info(ip).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });
            ip_results
        } else {
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("IpCheck.ing Maxmind");
                };

                let Ok(result) = client_v4.get("https://4.ipcheck.ing/").send().await else {
                    return request_error_ip_result("IpCheck.ing Maxmind", "Unable to connect");
                };

                let Ok(text) = result.text().await else {
                    return parse_ip_error_ip_result("IpCheck.ing Maxmind", "Unable to parse html");
                };

                let text = text.trim();

                let Ok(ip) = IpAddr::from_str(text) else {
                    return parse_ip_error_ip_result("IpCheck.ing Maxmind", text);
                };

                let mut result_without_time = get_maxmind_info(ip).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v4) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error("IpCheck.ing Maxmind");
                };

                let Ok(result) = client_v4.get("https://6.ipcheck.ing/").send().await else {
                    return request_error_ip_result("IpCheck.ing Maxmind", "Unable to connect");
                };

                let Ok(text) = result.text().await else {
                    return parse_ip_error_ip_result("IpCheck.ing Maxmind", "Unable to parse html");
                };

                let text = text.trim();

                let Ok(ip) = IpAddr::from_str(text) else {
                    return parse_ip_error_ip_result("IpCheck.ing Maxmind", text);
                };

                let mut result_without_time = get_maxmind_info(ip).await;
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

async fn get_maxmind_info(ip: IpAddr) -> IpResult {
    let Ok(client) = create_reqwest_client(None).await else {
        return create_reqwest_client_error("IpCheck.ing Maxmind");
    };

    let mut headers = header::HeaderMap::new();
    headers.insert("referer", "https://ipcheck.ing/".parse().unwrap());
    headers.insert("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".parse().unwrap());
    headers.insert("content-type", "application/json".parse().unwrap());

    let Ok(res) = client
        .get(format!("https://ipcheck.ing/api/maxmind?ip={ip}&lang=en"))
        .headers(headers)
        .send()
        .await
    else {
        return request_error_ip_result("IpCheck.ing Maxmind", "Unable to connect");
    };

    #[derive(Deserialize, Serialize)]
    struct MaxmindResp {
        ip: IpAddr,
        city: Option<String>,
        country_name: Option<String>,
        region: Option<String>,
        latitude: Option<f64>,
        longitude: Option<f64>,
        asn: Option<String>,
        org: Option<String>,
    }

    let Ok(json) = res.json::<MaxmindResp>().await else {
        return json_parse_error_ip_result(
            "IpCheck.ing Maxmind",
            "Unable to parse the returned result into Json",
        );
    };

    let asn = json
        .asn
        .map(|asn| asn.replace("AS", "").trim().parse::<u32>().unwrap_or(0));

    IpResult {
        success: true,
        error: No,
        provider: "IpCheck.ing Maxmind".to_string(),
        ip: Some(ip),
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
            time_zone: None,
        }),
        risk: None,
        used_time: None,
    }
}
