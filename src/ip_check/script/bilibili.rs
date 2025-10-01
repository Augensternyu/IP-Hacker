// src/ip_check/script/bilibili.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, request_error_ip_result, Coordinates, IpResult,
    Region,
}; // 引入错误处理函数和结果结构体
use crate::ip_check::script::create_reqwest_client; // 引入 reqwest 客户端创建函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use serde::{Deserialize, Serialize}; // 引入 serde 的 Deserialize 和 Serialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 Bilibili 结构体
pub struct Bilibili;

// 为 Bilibili 实现 IpCheck trait
#[async_trait]
impl IpCheck for Bilibili {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            // 如果指定了 IP 地址
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // 创建仅使用 IPv4 的 reqwest 客户端
                let Ok(client) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("Bilibili");
                };

                // 发送 GET 请求
                let Ok(result) = client
                    .get(format!(
                        "https://api.live.bilibili.com/ip_service/v1/ip_service/get_ip_addr?ip={ip}"
                    ))
                    .send()
                    .await
                else {
                    return request_error_ip_result("Bilibili", "Unable to connect");
                };

                // 解析响应并计算耗时
                let mut result_without_time = parse_bilibili(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });
            let mut results = Vec::new();
            if let Ok(result) = handle.await {
                results.push(result);
            }
            results
        } else {
            // 如果未指定 IP 地址，则查询本机 IP
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // 创建仅使用 IPv4 的 reqwest 客户端
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("Bilibili");
                };

                // 发送 GET 请求
                let Ok(result) = client_v4
                    .get("https://api.live.bilibili.com/ip_service/v1/ip_service/get_ip_addr")
                    .send()
                    .await
                else {
                    return request_error_ip_result("Bilibili", "Unable to connect");
                };

                // 解析响应并计算耗时
                let mut result_without_time = parse_bilibili(result).await;
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

// 解析 Bilibili 的 API 响应
async fn parse_bilibili(response: Response) -> IpResult {
    // 定义用于反序列化 Bilibili API 响应的结构体
    #[derive(Deserialize, Serialize)]
    struct BilibiliResp {
        data: Data,
    }
    #[derive(Deserialize, Serialize)]
    struct Data {
        addr: IpAddr,
        country: Option<String>,
        province: Option<String>,
        city: Option<String>,
        isp: Option<String>,
        latitude: Option<String>,
        longitude: Option<String>,
    }

    // 将响应体解析为 JSON
    let json: BilibiliResp = match response.json().await {
        Ok(p) => p,
        Err(_) => {
            return json_parse_error_ip_result(
                "Bilibili",
                "Unable to parse the returned result into Json",
            );
        }
    };

    // 构建 IpResult
    IpResult {
        success: true,
        error: No,
        provider: "Bilibili".to_string(),
        ip: Some(json.data.addr),
        autonomous_system: None,
        region: Some(Region {
            country: json.data.country,
            province: json.data.province,
            city: json.data.city,
            coordinates: if let (Some(latitude), Some(longitude)) =
                (json.data.latitude, json.data.longitude)
            {
                Some(Coordinates { latitude, longitude })
            } else {
                None
            },
            time_zone: None,
        }),
        risk: None,
        used_time: None,
    }
}
