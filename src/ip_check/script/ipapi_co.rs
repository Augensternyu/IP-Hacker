// src/ip_check/script/ipapi_co.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, parse_ip_error_ip_result, request_error_ip_result, Coordinates, IpResult, Region,
    AS,
}; // 引入错误处理函数和结果结构体
use crate::ip_check::script::create_reqwest_client; // 引入 reqwest 客户端创建函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use serde::{Deserialize, Serialize}; // 引入 serde 的 Deserialize 和 Serialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 IPApiCo 结构体
pub struct IPApiCo;

// 为 IPApiCo 实现 IpCheck trait
#[async_trait]
impl IpCheck for IPApiCo {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            // 如果指定了 IP 地址
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // 创建 reqwest 客户端
                let Ok(client_v4) = create_reqwest_client(None).await else {
                    return create_reqwest_client_error("IpApi.co");
                };

                // 发送 GET 请求
                let Ok(result) = client_v4
                    .get(format!("https://ipapi.co/{ip}/json"))
                    .send()
                    .await
                else {
                    return request_error_ip_result("IpApi.co", "Unable to connect");
                };
                // 解析响应并计算耗时
                let mut result_without_time = parse_ipapi_co_info(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });
            vec![handle.await.unwrap_or(parse_ip_error_ip_result(
                "IpApi.co",
                "Unable to parse IpApi.co",
            ))]
        } else {
            // 如果未指定 IP 地址，则查询本机 IP
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // 创建仅使用 IPv4 的 reqwest 客户端
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("IpApi.co");
                };

                // 发送 GET 请求
                let Ok(result) = client_v4.get("https://ipapi.co/json").send().await else {
                    return request_error_ip_result("IpApi.co", "Unable to connect");
                };

                // 解析响应并计算耗时
                let mut result_without_time = parse_ipapi_co_info(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // 创建仅使用 IPv6 的 reqwest 客户端
                let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error("IpApi.co");
                };

                // 发送 GET 请求
                let Ok(result) = client_v6.get("https://ipapi.co/json").send().await else {
                    return request_error_ip_result("IpApi.co", "Unable to connect");
                };

                // 解析响应并计算耗时
                let mut result_without_time = parse_ipapi_co_info(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            // 等待并收集结果
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

// 解析 IpApi.co 的 API 响应
async fn parse_ipapi_co_info(response: Response) -> IpResult {
    // 定义用于反序列化 API 响应的结构体
    #[derive(Deserialize, Serialize, Debug)]
    struct IPApiCoResp {
        ip: Option<IpAddr>,
        city: Option<String>,
        region: Option<String>,
        country_name: Option<String>,
        latitude: Option<f64>,
        longitude: Option<f64>,
        timezone: Option<String>,
        asn: Option<String>,
        org: Option<String>,
    }

    // 将响应体解析为 JSON
    let Ok(json) = response.json::<IPApiCoResp>().await else {
        return request_error_ip_result("IpApi.co", "Unable to parse Json");
    };

    // 解析 ASN
    let asn = json
        .asn
        .map(|asn| asn.replace("AS", "").trim().parse::<u32>().unwrap_or(0));

    // 构建 IpResult
    IpResult {
        success: true,
        error: No,
        provider: "IpApi.co".to_string(),
        ip: json.ip,
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
            coordinates: if let (Some(latitude), Some(longitude)) = (json.latitude, json.longitude) {
                Some(Coordinates {
                    latitude: latitude.to_string(),
                    longitude: longitude.to_string(),
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
