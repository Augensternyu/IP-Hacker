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

// 定义 IpwhoIs 结构体
pub struct IpwhoIs;

// 为 IpwhoIs 实现 IpCheck trait
#[async_trait]
impl IpCheck for IpwhoIs {
    // 异步检查 IP 地址
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        // 此 API 不支持通过 IPv6 访问，因此所有句柄都将强制使用 IPv4。
        if let Some(ip) = ip {
            // --- 检查指定IP ---
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // 强制使用IPv4进行API访问
                let Ok(client) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("Ipwho.is");
                };

                let url = format!("https://ipwho.is/{ip}");
                let Ok(result) = client.get(url).send().await else {
                    return request_error_ip_result("Ipwho.is", "Unable to connect");
                };

                let mut result_without_time = parse_ipwho_is_resp(result).await;
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
                    return create_reqwest_client_error("Ipwho.is");
                };

                let url = "https://ipwho.is/";
                let Ok(result) = client_v4.get(url).send().await else {
                    return request_error_ip_result("Ipwho.is", "Unable to connect");
                };

                let mut result_without_time = parse_ipwho_is_resp(result).await;
                result_without_time.used_time = Some(time_start.elapsed());
                result_without_time
            });

            vec![handle_v4.await.unwrap()]
        }
    }
}

// 解析 Ipwho.is 的 API 响应
async fn parse_ipwho_is_resp(response: Response) -> IpResult {
    // 定义用于解析 JSON 响应的内部结构体
    #[derive(Deserialize, Serialize)]
    struct Resp {
        success: bool,
        message: Option<String>,
        ip: Option<IpAddr>,
        country: Option<String>,
        region: Option<String>,
        city: Option<String>,
        latitude: Option<f64>,
        longitude: Option<f64>,
        connection: Option<ConnectionData>,
        timezone: Option<TimezoneData>,
    }
    #[derive(Deserialize, Serialize)]
    struct ConnectionData {
        asn: Option<u32>,
        isp: Option<String>,
    }
    #[derive(Deserialize, Serialize)]
    struct TimezoneData {
        id: Option<String>,
    }

    // 解析 JSON
    let Ok(json) = response.json::<Resp>().await else {
        return json_parse_error_ip_result("Ipwho.is", "Unable to parse result into Json");
    };

    // 检查 API 是否返回成功
    if !json.success {
        let err_msg = json
            .message
            .unwrap_or_else(|| "API returned success=false".to_string());
        return request_error_ip_result("Ipwho.is", &err_msg);
    }

    // 检查响应中是否包含 IP 地址
    if json.ip.is_none() {
        return request_error_ip_result("Ipwho.is", "API response did not contain an IP address.");
    }

    let connection = json.connection.as_ref();
    let asn_num = connection.and_then(|c| c.asn);
    let isp_name = connection.and_then(|c| c.isp.clone());

    // 构建并返回 IpResult
    IpResult {
        success: true,
        error: No,
        provider: "Ipwho.is".to_string(),
        ip: json.ip,
        autonomous_system: {
            if let (Some(number), Some(name)) = (asn_num, isp_name) {
                Some(AS { number, name })
            } else {
                None
            }
        },
        region: Some(Region {
            country: json.country,
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
            time_zone: json.timezone.and_then(|tz| tz.id),
        }),
        risk: None, // API不提供风险信息
        used_time: None, // 耗时将在调用处设置
    }
}
