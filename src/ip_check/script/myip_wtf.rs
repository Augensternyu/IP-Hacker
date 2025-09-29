// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::RiskTag::Tor; // 引入 Tor 风险标签
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, not_support_error, request_error_ip_result, IpResult, Region,
    Risk, AS,
}; // 引入IP检查结果相关的结构体和函数
use crate::ip_check::script::create_reqwest_client; // 引入创建 reqwest 客户端的函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use serde::{Deserialize, Serialize}; // 引入 serde 的 Deserialize 和 Serialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 MyIpWtf 结构体
pub struct MyIpWtf;

// 为 MyIpWtf 实现 IpCheck trait
#[async_trait]
impl IpCheck for MyIpWtf {
    // 异步检查 IP 地址
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            // API 不支持查询指定 IP
            vec![not_support_error("MyIP.wtf")]
        } else {
            // --- 检查本机 IPv4 ---
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("MyIP.wtf");
                };

                let Ok(result) = client_v4.get("https://myip.wtf/json").send().await else {
                    return request_error_ip_result("MyIP.wtf", "Unable to connect");
                };

                let mut result_without_time = parse_myip_wtf_resp(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time); // 记录耗时
                result_without_time
            });

            // --- 检查本机 IPv6 ---
            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error("MyIP.wtf");
                };

                let Ok(result) = client_v6.get("https://myip.wtf/json").send().await else {
                    return request_error_ip_result("MyIP.wtf", "Unable to connect");
                };

                let mut result_without_time = parse_myip_wtf_resp(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            let mut results = Vec::new();
            if let Ok(result) = handle_v4.await
                && result.success {
                    results.push(result);
                }
            if let Ok(result) = handle_v6.await
                && result.success {
                    results.push(result);
                }
            results
        }
    }
}

// 解析 MyIP.wtf 的 API 响应
async fn parse_myip_wtf_resp(response: Response) -> IpResult {
    // 定义用于解析 JSON 响应的内部结构体
    #[derive(Deserialize, Serialize)]
    struct MyIpWtfResp {
        #[serde(rename = "YourFuckingIPAddress")]
        ip: Option<IpAddr>,

        #[serde(rename = "YourFuckingLocation")]
        location: Option<String>,

        #[serde(rename = "YourFuckingISP")]
        isp: Option<String>,

        #[serde(rename = "YourFuckingTorExit")]
        is_tor: Option<bool>,

        #[serde(rename = "YourFuckingCity")]
        city: Option<String>,

        #[serde(rename = "YourFuckingCountry")]
        country: Option<String>,
    }

    if !response.status().is_success() {
        return request_error_ip_result("MyIP.wtf", "Server returned an error");
    }

    // 解析 JSON
    let Ok(json) = response.json::<MyIpWtfResp>().await else {
        return json_parse_error_ip_result(
            "MyIP.wtf",
            "Unable to parse the returned result into Json",
        );
    };

    // 从 location 字段中提取地区信息
    let region = if let Some(location) = json.location {
        let parts: Vec<&str> = location.split(", ").collect();
        // "Nanning, GX, China" -> parts[1] is "GX"
        parts.get(1).map(|s| (*s).to_string())
    } else {
        None
    };

    // 构建并返回 IpResult
    IpResult {
        success: true,
        error: No,
        provider: "MyIP.wtf".to_string(),
        ip: json.ip,
        autonomous_system: {
            json.isp.map(|isp| AS {
                number: 0, // API不提供ASN号码
                name: isp,
            })
        },
        region: Some(Region {
            country: json.country,
            region,
            city: json.city,
            coordinates: None, // API不提供坐标信息
            time_zone: None,   // API不提供时区信息
        }),
        risk: Some(Risk {
            risk: None,
            tags: {
                if Some(true) == json.is_tor {
                    Some(vec![Tor])
                } else {
                    None
                }
            },
        }),
        used_time: None, // 耗时将在调用处设置
    }
}
