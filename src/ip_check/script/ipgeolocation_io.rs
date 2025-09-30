// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, request_error_ip_result, Coordinates, IpResult,
    Region,
}; // 引入IP检查结果相关的结构体和函数
use crate::ip_check::script::create_reqwest_client; // 引入创建 reqwest 客户端的函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use serde::{Deserialize, Serialize}; // 引入 serde 的 Deserialize 和 Serialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 IpgeolocationIo 结构体
pub struct IpgeolocationIo;

// 定义 API 密钥
const API_KEY: &str = "14c7928d2aef416287e034ee91cd360d";

// 为 IpgeolocationIo 实现 IpCheck trait
#[async_trait]
impl IpCheck for IpgeolocationIo {
    // 异步检查 IP 地址
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        // API不支持IPv6访问, 所有请求强制走IPv4
        if let Some(ip) = ip {
            // --- 检查指定IP ---
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // 强制使用IPv4进行API访问
                let Ok(client) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("IpGeolocation.io");
                };

                let url = format!("https://api.ipgeolocation.io/v2/ipgeo?apiKey={API_KEY}&ip={ip}");
                let Ok(result) = client.get(url).send().await else {
                    return request_error_ip_result("IpGeolocation.io", "Unable to connect");
                };

                let mut result_without_time = parse_ipgeolocation_io_resp(result).await;
                result_without_time.used_time = Some(time_start.elapsed()); // 记录耗时
                result_without_time
            });
            vec![handle.await.unwrap()]
        } else {
            // --- 检查本机IP ---
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // 强制使用IPv4进行API访问
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("IpGeolocation.io");
                };

                let url = format!("https://api.ipgeolocation.io/v2/ipgeo?apiKey={API_KEY}");
                let Ok(result) = client_v4.get(url).send().await else {
                    return request_error_ip_result("IpGeolocation.io", "Unable to connect");
                };

                let mut result_without_time = parse_ipgeolocation_io_resp(result).await;
                result_without_time.used_time = Some(time_start.elapsed());
                result_without_time
            });

            vec![handle_v4.await.unwrap()]
        }
    }
}

// 解析 Ipgeolocation.io 的 API 响应
async fn parse_ipgeolocation_io_resp(response: Response) -> IpResult {
    // 定义用于解析 JSON 响应的内部结构体
    #[derive(Deserialize, Serialize)]
    struct Resp {
        ip: Option<IpAddr>,
        location: Option<LocationData>,
        message: Option<String>, // 用于捕获API的错误信息
    }
    #[derive(Deserialize, Serialize)]
    struct LocationData {
        country_name: Option<String>,
        state_prov: Option<String>,
        city: Option<String>,
        latitude: Option<String>,
        longitude: Option<String>,
    }

    // 解析 JSON
    let Ok(json) = response.json::<Resp>().await else {
        return json_parse_error_ip_result("IpGeolocation.io", "Unable to parse result into Json");
    };

    // 检查 API 是否返回错误信息
    if let Some(msg) = json.message {
        return request_error_ip_result("IpGeolocation.io", &msg);
    }

    if json.ip.is_none() {
        return request_error_ip_result(
            "IpGeolocation.io",
            "API response did not contain an IP address.",
        );
    }

    let location = json.location;

    // 构建并返回 IpResult
    IpResult {
        success: true,
        error: No,
        provider: "IpGeolocation.io".to_string(),
        ip: json.ip,
        autonomous_system: None, // API不提供ASN/ISP信息
        region: {
            location.map(|loc| Region {
                country: loc.country_name,
                region: loc.state_prov,
                city: loc.city,
                coordinates: if let (Some(latitude), Some(longitude)) = (loc.latitude, loc.longitude) {
                    Some(Coordinates { latitude, longitude })
                } else {
                    None
                },
                time_zone: None, // API不提供标准时区标识
            })
        },
        risk: None, // API不提供风险信息
        used_time: None, // 耗时将在调用处设置
    }
}
