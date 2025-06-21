use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    AS, Coordinates, IpResult, Region, Risk, create_reqwest_client_error,
    json_parse_error_ip_result, request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use serde_json::Value;
// 导入 Value 类型
use std::net::IpAddr;

pub struct Ip234In;

#[async_trait]
impl IpCheck for Ip234In {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client) = create_reqwest_client(None).await else {
                    return create_reqwest_client_error("Ip234.in");
                };

                let Ok(geo_resp) = client
                    .get(format!("https://ip234.in/search_ip?ip={ip}"))
                    .send()
                    .await
                else {
                    return request_error_ip_result("Ip234.in", "Unable to connect for geo info");
                };

                let mut ip_result = parse_ip234_in_search_resp(geo_resp).await;
                if !ip_result.success {
                    return ip_result;
                }

                let Ok(fraud_resp) = client
                    .get(format!("https://ip234.in/fraud_check?ip={ip}"))
                    .send()
                    .await
                else {
                    ip_result.used_time = Some(time_start.elapsed());
                    return ip_result;
                };

                if let Some(score) = parse_ip234_in_fraud_resp(fraud_resp).await {
                    ip_result.risk = Some(Risk {
                        risk: Some(score),
                        tags: None,
                    });
                }

                ip_result.used_time = Some(time_start.elapsed());
                ip_result
            });
            vec![handle.await.unwrap()]
        } else {
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("Ip234.in");
                };

                let Ok(local_resp) = client_v4.get("https://ip234.in/ip.json").send().await else {
                    return request_error_ip_result("Ip234.in", "Unable to connect for local IP");
                };

                let (mut ip_result, ip_addr_option) = parse_ip234_in_local_resp(local_resp).await;
                if !ip_result.success {
                    return ip_result;
                }

                if let Some(ip_addr) = ip_addr_option {
                    let Ok(fraud_resp) = client_v4
                        .get(format!("https://ip234.in/fraud_check?ip={ip_addr}"))
                        .send()
                        .await
                    else {
                        ip_result.used_time = Some(time_start.elapsed());
                        return ip_result;
                    };

                    if let Some(score) = parse_ip234_in_fraud_resp(fraud_resp).await {
                        ip_result.risk = Some(Risk {
                            risk: Some(score),
                            tags: None,
                        });
                    }
                }

                ip_result.used_time = Some(time_start.elapsed());
                ip_result
            });

            let mut results = Vec::new();
            if let Ok(result) = handle_v4.await {
                results.push(result);
            }
            results
        }
    }
}

async fn parse_ip234_in_search_resp(response: Response) -> IpResult {
    #[derive(Deserialize, Serialize)]
    struct SearchResp {
        code: i32,
        data: Option<Data>,
        msg: Option<String>,
    }
    #[derive(Deserialize, Serialize)]
    #[serde(rename_all = "snake_case")] // 自动处理驼峰到蛇形
    struct Data {
        ip: Option<IpAddr>,
        city: Option<String>,
        organization: Option<String>,
        asn: Option<u32>,
        country: Option<String>,
        // 关键修正：使用 Value 类型接收
        latitude: Option<Value>,
        longitude: Option<Value>,
        timezone: Option<String>,
        region: Option<String>,
    }

    let Ok(json) = response.json::<SearchResp>().await else {
        return json_parse_error_ip_result("Ip234.in", "Unable to parse search result into Json");
    };

    if json.code != 0 {
        let err_msg = json
            .msg
            .unwrap_or_else(|| "Server returned an error".to_string());
        return json_parse_error_ip_result("Ip234.in", &err_msg);
    }

    let Some(data) = json.data else {
        return json_parse_error_ip_result(
            "Ip234.in",
            "Server returned success code but no data payload",
        );
    };

    // 关键逻辑：手动处理经纬度
    let lat_str = data.latitude.and_then(|v| {
        v.as_str()
            .map(ToString::to_string)
            .or_else(|| v.as_f64().map(|f| f.to_string()))
    });
    let lon_str = data.longitude.and_then(|v| {
        v.as_str()
            .map(ToString::to_string)
            .or_else(|| v.as_f64().map(|f| f.to_string()))
    });

    IpResult {
        success: true,
        error: No,
        provider: "Ip234.in".to_string(),
        ip: data.ip,
        autonomous_system: {
            if let (Some(asn), Some(org)) = (data.asn, data.organization) {
                Some(AS {
                    number: asn,
                    name: org,
                })
            } else {
                None
            }
        },
        region: Some(Region {
            country: data.country,
            region: data.region,
            city: data.city,
            coordinates: if let (Some(lat), Some(lon)) = (lat_str, lon_str) {
                Some(Coordinates { lat, lon })
            } else {
                None
            },
            time_zone: data.timezone,
        }),
        risk: None,
        used_time: None,
    }
}

async fn parse_ip234_in_local_resp(response: Response) -> (IpResult, Option<IpAddr>) {
    #[derive(Deserialize, Serialize)]
    struct LocalResp {
        ip: Option<IpAddr>,
        city: Option<String>,
        organization: Option<String>,
        asn: Option<u32>,
        country: Option<String>,
        // 同样应用修正
        latitude: Option<Value>,
        longitude: Option<Value>,
        timezone: Option<String>,
        region: Option<String>,
    }

    let Ok(json) = response.json::<LocalResp>().await else {
        return (
            json_parse_error_ip_result("Ip234.in", "Unable to parse local result into Json"),
            None,
        );
    };

    let lat_str = json.latitude.and_then(|v| {
        v.as_str()
            .map(ToString::to_string)
            .or_else(|| v.as_f64().map(|f| f.to_string()))
    });
    let lon_str = json.longitude.and_then(|v| {
        v.as_str()
            .map(ToString::to_string)
            .or_else(|| v.as_f64().map(|f| f.to_string()))
    });

    let ip_addr = json.ip;
    let result = IpResult {
        success: true,
        error: No,
        provider: "Ip234.in".to_string(),
        ip: json.ip,
        autonomous_system: {
            if let (Some(asn), Some(org)) = (json.asn, json.organization) {
                Some(AS {
                    number: asn,
                    name: org,
                })
            } else {
                None
            }
        },
        region: Some(Region {
            country: json.country,
            region: json.region,
            city: json.city,
            coordinates: if let (Some(lat), Some(lon)) = (lat_str, lon_str) {
                Some(Coordinates { lat, lon })
            } else {
                None
            },
            time_zone: json.timezone,
        }),
        risk: None,
        used_time: None,
    };
    (result, ip_addr)
}

async fn parse_ip234_in_fraud_resp(response: Response) -> Option<u16> {
    #[derive(Deserialize, Serialize)]
    struct FraudResp {
        code: i32,
        data: Option<Data>,
    }
    #[derive(Deserialize, Serialize)]
    struct Data {
        score: Option<u16>,
    }

    let Ok(json) = response.json::<FraudResp>().await else {
        return None;
    };

    if json.code != 0 {
        return None;
    }

    json.data.and_then(|d| d.score)
}
