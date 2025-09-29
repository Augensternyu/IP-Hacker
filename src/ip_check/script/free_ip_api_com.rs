// src/ip_check/script/free_ip_api_com.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::RiskTag::Proxy; // 引入风险标签
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, request_error_ip_result, Coordinates, IpResult, Region,
    Risk,
}; // 引入错误处理函数和结果结构体
use crate::ip_check::script::create_reqwest_client; // 引入 reqwest 客户端创建函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use serde::{Deserialize, Serialize}; // 引入 serde 的 Deserialize 和 Serialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 FreeIpApiCom 结构体
pub struct FreeIpApiCom;

// 为 FreeIpApiCom 实现 IpCheck trait
#[async_trait]
impl IpCheck for FreeIpApiCom {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            // 如果指定了 IP 地址
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();

                // 创建 reqwest 客户端
                let Ok(client) = create_reqwest_client(None).await else {
                    return create_reqwest_client_error("FreeIpApi.com");
                };

                // 发送 GET 请求
                let Ok(result) = client
                    .get(format!("https://freeipapi.com/api/json/{ip}"))
                    .send()
                    .await
                else {
                    return request_error_ip_result("FreeIpApi.com", "Unable to connect");
                };

                // 解析响应并计算耗时
                let mut result_without_time = parse_free_ip_api_com_resp(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });
            vec![handle.await.unwrap_or(json_parse_error_ip_result(
                "FreeIpApi.com",
                "Unable to parse json",
            ))]
        } else {
            // 如果未指定 IP 地址，则查询本机 IP
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();

                // 创建仅使用 IPv4 的 reqwest 客户端
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("FreeIpApi.com");
                };

                // 发送 GET 请求
                let Ok(result) = client_v4.get("https://freeipapi.com/api/json").send().await
                else {
                    return request_error_ip_result("FreeIpApi.com", "Unable to connect");
                };

                // 解析响应并计算耗时
                let mut result_without_time = parse_free_ip_api_com_resp(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();

                // 创建仅使用 IPv6 的 reqwest 客户端
                let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error("FreeIpApi.com");
                };

                // 发送 GET 请求
                let Ok(result) = client_v6.get("https://freeipapi.com/api/json").send().await
                else {
                    return request_error_ip_result("FreeIpApi.com", "Unable to connect");
                };

                // 解析响应并计算耗时
                let mut result_without_time = parse_free_ip_api_com_resp(result).await;
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

// 解析 FreeIpApi.com 的 API 响应
async fn parse_free_ip_api_com_resp(response: Response) -> IpResult {
    // 定义用于反序列化 API 响应的结构体
    #[derive(Deserialize, Serialize)]
    struct FreeIpApiComResp {
        #[serde(rename = "ipAddress")]
        ip: Option<IpAddr>,

        latitude: Option<f64>,
        longitude: Option<f64>,

        #[serde(rename = "countryName")]
        country_name: Option<String>,

        #[serde(rename = "cityName")]
        city_name: Option<String>,

        #[serde(rename = "regionName")]
        region_name: Option<String>,

        #[serde(rename = "isProxy")]
        is_proxy: Option<bool>,
    }

    // 将响应体解析为 JSON
    let Ok(json) = response.json::<FreeIpApiComResp>().await else {
        return json_parse_error_ip_result(
            "FreeIpApi.com",
            "Unable to parse the returned result into Json",
        );
    };

    // 构建 IpResult
    IpResult {
        success: true,
        error: No,
        provider: "FreeIpApi.com".to_string(),
        ip: json.ip,
        autonomous_system: None,
        region: Some(Region {
            country: json.country_name,
            region: json.region_name,
            city: json.city_name,
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
            time_zone: None,
        }),
        risk: Some(Risk {
            risk: None,
            tags: {
                if Some(true) == json.is_proxy {
                    Some(vec![Proxy])
                } else {
                    None
                }
            },
        }),
        used_time: None,
    }
}
