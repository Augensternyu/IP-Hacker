// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, not_support_error, request_error_ip_result, Coordinates, IpResult,
    Region,
}; // 引入IP检查结果相关的结构体和函数
use crate::ip_check::script::create_reqwest_client; // 引入创建 reqwest 客户端的函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use serde::{Deserialize, Serialize}; // 引入 serde 的 Deserialize 和 Serialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 MyIPLa 结构体
pub struct MyIPLa;

// 为 MyIPLa 实现 IpCheck trait
#[async_trait]
impl IpCheck for MyIPLa {
    // 异步检查 IP 地址
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            // API 不支持查询指定 IP
            vec![not_support_error("Myip.La")]
        } else {
            // --- 检查本机 IPv4 ---
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("Myip.La");
                };

                let Ok(result) = client_v4.get("https://api.myip.la/en?json").send().await else {
                    return request_error_ip_result("Myip.La", "Unable to connect");
                };

                let mut result_without_time = parse_myip_la_info(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time); // 记录耗时
                result_without_time
            });

            // --- 检查本机 IPv6 ---
            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error("Myip.La");
                };

                let Ok(result) = client_v6.get("https://api.myip.la/en?json").send().await else {
                    return request_error_ip_result("Myip.La", "Unable to connect");
                };

                let mut result_without_time = parse_myip_la_info(result).await;
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

// 解析 Myip.La 的 API 响应
async fn parse_myip_la_info(response: Response) -> IpResult {
    // 定义用于解析 JSON 响应的内部结构体
    #[derive(Deserialize, Serialize)]
    struct MyIPLaResp {
        ip: Option<IpAddr>,
        location: Location,
    }
    #[derive(Deserialize, Serialize)]
    struct Location {
        city: Option<String>,
        country_name: Option<String>,
        province: Option<String>,
        latitude: Option<String>,
        longitude: Option<String>,
    }

    // 解析 JSON
    let Ok(json) = response.json::<MyIPLaResp>().await else {
        return request_error_ip_result("MyIP.La", "Unable to parse Json");
    };

    // 构建并返回 IpResult
    IpResult {
        success: true,
        error: No,
        provider: "MyIP.La".to_string(),
        ip: json.ip,
        autonomous_system: None, // API不提供ASN信息
        region: Some(Region {
            country: json.location.country_name,
            province: json.location.province,
            city: json.location.city,
            coordinates: if let (Some(lat), Some(lon)) =
                (json.location.latitude, json.location.longitude)
            {
                Some(Coordinates { latitude: lat, longitude: lon })
            } else {
                None
            },
            time_zone: None, // API不提供时区信息
        }),
        risk: None, // API不提供风险信息
        used_time: None, // 耗时将在调用处设置
    }
}
