use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::RiskTag::{Hosting, Proxy, Tor};
use crate::ip_check::ip_result::{
    AS, Coordinates, IpResult, Region, Risk, create_reqwest_client_error,
    json_parse_error_ip_result, not_support_error, request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use reqwest::{Response, header};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct IpLarkCom;

#[async_trait]
impl IpCheck for IpLarkCom {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            vec![not_support_error("IpLark.com")]
        } else {
            let mut headers = header::HeaderMap::new();
            headers.insert("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".parse().unwrap());
            headers.insert("accept-language", "zh-CN,zh;q=0.9".parse().unwrap());
            headers.insert("cache-control", "max-age=0".parse().unwrap());
            headers.insert("dnt", "1".parse().unwrap());
            headers.insert("priority", "u=0, i".parse().unwrap());
            headers.insert(
                "sec-ch-ua",
                "\"Google Chrome\";v=\"137\", \"Chromium\";v=\"137\", \"Not/A)Brand\";v=\"24\""
                    .parse()
                    .unwrap(),
            );
            headers.insert("sec-ch-ua-mobile", "?0".parse().unwrap());
            headers.insert("sec-ch-ua-platform", "\"Linux\"".parse().unwrap());
            headers.insert("sec-fetch-dest", "document".parse().unwrap());
            headers.insert("sec-fetch-mode", "navigate".parse().unwrap());
            headers.insert("sec-fetch-site", "none".parse().unwrap());
            headers.insert("sec-fetch-user", "?1".parse().unwrap());
            headers.insert("upgrade-insecure-requests", "1".parse().unwrap());
            headers.insert("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36".parse().unwrap());

            let handle_v4 = tokio::spawn(async move {
                let Ok(client_v4) = create_reqwest_client(None, None).await else {
                    return create_reqwest_client_error("IpLark.com");
                };

                let Ok(result) = client_v4
                    .get("https://iplark.com/ipstack")
                    .headers(headers)
                    .send()
                    .await
                else {
                    return request_error_ip_result("IpLark.com", "Unable to connect");
                };

                parse_ip_lark_com_resp(result).await
            });

            let mut results = Vec::new();
            if let Ok(result) = handle_v4.await {
                results.push(result);
            }
            results
        }
    }
}

async fn parse_ip_lark_com_resp(response: Response) -> IpResult {
    #[derive(Deserialize, Serialize)]
    struct IpLarkComResp {
        ip: IpAddr,
        country_name: Option<String>,
        region_name: Option<String>,
        city: Option<String>,
        latitude: Option<f64>,
        longitude: Option<f64>,
        time_zone: TZ,
        connection: CONN,
        security: Security,
    }

    #[derive(Deserialize, Serialize)]
    struct TZ {
        timezone: Option<String>,
    }

    #[derive(Deserialize, Serialize)]
    struct CONN {
        asn: Option<i32>,
        isp: Option<String>,
    }

    #[derive(Deserialize, Serialize)]
    struct Security {
        is_proxy: bool,
        is_tor: bool,
        hosting_facility: bool,
    }
    let Ok(json) = response.json::<IpLarkComResp>().await else {
        return json_parse_error_ip_result(
            "IpLark.com",
            "Unable to parse the returned result into Json",
        );
    };

    IpResult {
        success: true,
        error: No,
        provider: "IpLark.com".to_string(),
        ip: Some(json.ip),
        autonomous_system: {
            if let (Some(asn), Some(isp)) = (json.connection.asn, json.connection.isp) {
                Some(AS {
                    number: asn as u32,
                    name: isp,
                })
            } else {
                None
            }
        },
        region: Some(Region {
            country: json.country_name,
            region: json.region_name,
            city: json.city,
            coordinates: {
                if let (Some(lat), Some(lon)) = (json.latitude, json.longitude) {
                    Some(Coordinates {
                        lat: lat.to_string(),
                        lon: lon.to_string(),
                    })
                } else {
                    None
                }
            },
            time_zone: json.time_zone.timezone,
        }),
        risk: {
            let mut vec = vec![];
            if json.security.is_proxy {
                vec.push(Proxy);
            }
            if json.security.is_tor {
                vec.push(Tor);
            }
            if json.security.hosting_facility {
                vec.push(Hosting);
            }

            Some(Risk {
                risk: None,
                tags: Some(vec),
            })
        },
    }
}
