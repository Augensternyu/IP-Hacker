// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, request_error_ip_result, Coordinates, IpResult, Region,
    AS,
}; // 引入IP检查结果相关的结构体和函数
use crate::ip_check::script::create_reqwest_client; // 引入创建 reqwest 客户端的函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use serde::{Deserialize, Serialize}; // 引入 serde 的 Deserialize 和 Serialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 IpWhoisApp 结构体
pub struct IpWhoisApp;

// 为 IpWhoisApp 实现 IpCheck trait
#[async_trait]
impl IpCheck for IpWhoisApp {
    // 异步检查 IP 地址
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            // --- 检查指定IP ---
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client) = create_reqwest_client(None).await else {
                    return create_reqwest_client_error("IpWhois.app");
                };

                let Ok(result) = client
                    .get(format!("https://ipwhois.app/json/{ip}?format=json"))
                    .send()
                    .await
                else {
                    return request_error_ip_result("IpWhois.app", "Unable to connect");
                };

                let mut result_without_time = parse_ipwhois_app_resp(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time); // 记录耗时
                result_without_time
            });
            vec![handle.await.unwrap_or(json_parse_error_ip_result(
                "IpWhois.app",
                "Unable to parse json",
            ))]
        } else {
            // --- 检查本机IP (仅 v4) ---
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("IpWhois.app");
                };

                let Ok(result) = client_v4
                    .get("https://ipwhois.app/json/?format=json")
                    .send()
                    .await
                else {
                    return request_error_ip_result("IpWhois.app", "Unable to connect");
                };

                let mut result_without_time = parse_ipwhois_app_resp(result).await;
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

// 解析 IpWhois.app 的 API 响应
async fn parse_ipwhois_app_resp(response: Response) -> IpResult {
    // 定义用于解析 JSON 响应的内部结构体
    #[derive(Deserialize, Serialize)]
    struct IpWhoisAppResp {
        ip: Option<IpAddr>,
        success: bool,
        country: Option<String>,
        region: Option<String>,
        city: Option<String>,
        latitude: Option<f64>,
        longitude: Option<f64>,
        asn: Option<String>,
        isp: Option<String>,
        timezone: Option<String>,
    }

    // 解析 JSON
    let Ok(json) = response.json::<IpWhoisAppResp>().await else {
        return json_parse_error_ip_result(
            "IpWhois.app",
            "Unable to parse the returned result into Json",
        );
    };

    // 检查 API 是否返回成功
    if !json.success {
        return json_parse_error_ip_result("IpWhois.app", "Server returned an error");
    }

    // 构建并返回 IpResult
    IpResult {
        success: true,
        error: No,
        provider: "IpWhois.app".to_string(),
        ip: json.ip,
        autonomous_system: {
            if let (Some(asn), Some(isp)) = (json.asn, json.isp) {
                Some(AS {
                    number: asn.replace("AS", "").parse::<u32>().unwrap_or(0),
                    name: isp,
                })
            } else {
                None
            }
        },
        region: Some(Region {
            country: json.country,
            province: json.region,
            city: json.city,
            coordinates: {
                if let (Some(lat), Some(lon)) = (json.latitude, json.longitude) {
                    Some(Coordinates {
                        latitude: lat.to_string(),
                        longitude: lon.to_string(),
                    })
                } else {
                    None
                }
            },
            time_zone: json.timezone,
        }),
        risk: None, // API不提供风险信息
        used_time: None, // 耗时将在调用处设置
    }
}
