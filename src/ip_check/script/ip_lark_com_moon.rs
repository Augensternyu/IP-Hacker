// src/ip_check/script/ip_lark_com_moon.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, not_support_error, request_error_ip_result, Coordinates,
    IpResult, Region,
}; // 引入错误处理函数和结果结构体
use crate::ip_check::script::create_reqwest_client; // 引入 reqwest 客户端创建函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use serde::{Deserialize, Serialize}; // 引入 serde 的 Deserialize 和 Serialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 IpLarkComMoon 结构体
pub struct IpLarkComMoon;

// 为 IpLarkComMoon 实现 IpCheck trait
#[async_trait]
impl IpCheck for IpLarkComMoon {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            // 此 API 不支持查询指定 IP
            vec![not_support_error("IpLark.com Moon")]
        } else {
            // 异步查询 IPv4 地址
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // 创建仅使用 IPv4 的 reqwest 客户端
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("IpLark.com Moon");
                };

                // 发送 GET 请求
                let Ok(result) = client_v4
                    .get("https://iplark.com/ipapi/public/ipinfo?db=moon")
                    .send()
                    .await
                else {
                    return request_error_ip_result("IpLark.com Moon", "Unable to connect");
                };

                // 解析响应并计算耗时
                let mut result_without_time = parse_ip_lark_com_moon(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            // 异步查询 IPv6 地址
            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // 创建仅使用 IPv6 的 reqwest 客户端
                let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error("IpLark.com Moon");
                };

                // 发送 GET 请求
                let Ok(result) = client_v6
                    .get("https://6.iplark.com/ipapi/public/ipinfo?db=moon")
                    .send()
                    .await
                else {
                    return request_error_ip_result("IpLark.com Moon", "Unable to connect");
                };

                // 解析响应并计算耗时
                let mut result_without_time = parse_ip_lark_com_moon(result).await;
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

// 解析 IpLark.com Moon 的 API 响应
async fn parse_ip_lark_com_moon(response: Response) -> IpResult {
    // 定义用于反序列化 API 响应的结构体
    #[derive(Deserialize, Serialize)]
    struct IpLarkComMoonResp {
        data: Data,
    }
    #[derive(Deserialize, Serialize)]
    struct Data {
        ip: IpAddr,
        country: Option<String>,
        province: Option<String>,
        city: Option<String>,
        latitude: Option<f64>,
        longitude: Option<f64>,
    }

    // 将响应体解析为 JSON
    let Ok(json) = response.json::<IpLarkComMoonResp>().await else {
        return json_parse_error_ip_result(
            "IpLark.com Moon",
            "Unable to parse the returned result into Json",
        );
    };

    // 构建 IpResult
    IpResult {
        success: true,
        error: No,
        provider: "IpLark.com Moon".to_string(),
        ip: Some(json.data.ip),
        autonomous_system: None,
        region: Some(Region {
            country: json.data.country,
            region: json.data.province,
            city: json.data.city,
            coordinates: if let (Some(lat), Some(lon)) = (json.data.latitude, json.data.longitude) {
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
