use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    AS, Coordinates, IpResult, Region, create_reqwest_client_error, json_parse_error_ip_result,
    parse_ip_error_ip_result, request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use reqwest::header;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;

pub struct IpChecking;

#[async_trait]
impl IpCheck for IpChecking {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            vec![get_ipcheck_ing_info(ip).await]
        } else {
            let handle_v4 = tokio::spawn(async move {
                let Ok(client_v4) = create_reqwest_client(Some("curl/8.11.1"), Some(false)).await
                else {
                    return create_reqwest_client_error("IpCheck.ing");
                };

                let Ok(result) = client_v4.get("https://4.ipcheck.ing/").send().await else {
                    return request_error_ip_result("IpCheck.ing", "Unable to connect");
                };

                let Ok(text) = result.text().await else {
                    return parse_ip_error_ip_result("IpCheck.ing", "Unable to parse html");
                };

                let text = text.trim();

                let Ok(ip) = IpAddr::from_str(text) else {
                    return parse_ip_error_ip_result("IpCheck.ing", text);
                };
                get_ipcheck_ing_info(ip).await
            });

            let handle_v6 = tokio::spawn(async move {
                let Ok(client_v4) = create_reqwest_client(Some("curl/8.11.1"), Some(true)).await
                else {
                    return create_reqwest_client_error("IpCheck.ing");
                };

                let Ok(result) = client_v4.get("https://6.ipcheck.ing/").send().await else {
                    return request_error_ip_result("IpCheck.ing", "Unable to connect");
                };

                let Ok(text) = result.text().await else {
                    return parse_ip_error_ip_result("IpCheck.ing", "Unable to parse html");
                };

                let text = text.trim();

                let Ok(ip) = IpAddr::from_str(text) else {
                    return parse_ip_error_ip_result("IpCheck.ing", text);
                };
                get_ipcheck_ing_info(ip).await
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

async fn get_ipcheck_ing_info(ip: IpAddr) -> IpResult {
    let Ok(client) = create_reqwest_client(None, None).await else {
        return create_reqwest_client_error("IpCheck.ing");
    };

    let mut headers = header::HeaderMap::new();
    headers.insert("referer", "https://ipcheck.ing/".parse().unwrap());
    headers.insert("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".parse().unwrap());
    headers.insert("content-type", "application/json".parse().unwrap());

    let Ok(res) = client
        .get(format!(
            "https://ipcheck.ing/api/ipchecking?ip={ip}&lang=en"
        ))
        .headers(headers)
        .send()
        .await
    else {
        return request_error_ip_result("IpCheck.ing", "Unable to connect");
    };

    #[derive(Deserialize, Serialize)]
    struct IpCheckingResp {
        ip: IpAddr,
        city: Option<String>,
        country_name: Option<String>,
        region: Option<String>,
        latitude: Option<f64>,
        longitude: Option<f64>,
        asn: Option<String>,
        org: Option<String>,
    }

    let Ok(json) = res.json::<IpCheckingResp>().await else {
        return json_parse_error_ip_result(
            "IpCheck.ing",
            "Unable to parse the returned result into Json",
        );
    };

    let asn = json
        .asn
        .map(|asn| asn.replace("AS", "").trim().parse::<u32>().unwrap_or(0));

    IpResult {
        success: true,
        error: No,
        provider: "IpCheck.ing".to_string(),
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
