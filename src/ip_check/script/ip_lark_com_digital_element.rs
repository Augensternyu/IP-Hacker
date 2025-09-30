// src/ip_check/script/ip_lark_com_digital_element.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::RiskTag::{Hosting, Mobile, Other, Proxy, Tor}; // 引入风险标签
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, not_support_error, request_error_ip_result, Coordinates, IpResult,
    Region, Risk, AS,
}; // 引入错误处理函数和结果结构体
use crate::ip_check::script::create_reqwest_client; // 引入 reqwest 客户端创建函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use serde::{Deserialize, Serialize}; // 引入 serde 的 Deserialize 和 Serialize
use std::collections::HashSet; // 引入 HashSet 用于去重
use std::net::IpAddr; // 引入 IpAddr

// 定义 IpLarkComDigitalElement 结构体
pub struct IpLarkComDigitalElement;

// 为 IpLarkComDigitalElement 实现 IpCheck trait
#[async_trait]
impl IpCheck for IpLarkComDigitalElement {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            // 此 API 不支持查询指定 IP
            vec![not_support_error("IpLark.com Digital Element")]
        } else {
            // 异步查询 IPv4 地址
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // 创建仅使用 IPv4 的 reqwest 客户端
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("IpLark.com Digital Element");
                };

                // 发送 GET 请求
                let Ok(result) = client_v4
                    .get("https://iplark.com/ipapi/public/ipinfo?db=digital")
                    .send()
                    .await
                else {
                    return request_error_ip_result(
                        "IpLark.com Digital Element",
                        "Unable to connect",
                    );
                };

                // 解析响应并计算耗时
                let mut result_without_time = parse_ip_lark_com_digital_element(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            // 异步查询 IPv6 地址
            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // 创建仅使用 IPv6 的 reqwest 客户端
                let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error("IpLark.com Digital Element");
                };

                // 发送 GET 请求
                let Ok(result) = client_v6
                    .get("https://6.iplark.com/ipapi/public/ipinfo?db=digital")
                    .send()
                    .await
                else {
                    return request_error_ip_result(
                        "IpLark.com Digital Element",
                        "Unable to connect",
                    );
                };

                // 解析响应并计算耗时
                let mut result_without_time = parse_ip_lark_com_digital_element(result).await;
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

// 解析 IpLark.com Digital Element 的 API 响应
async fn parse_ip_lark_com_digital_element(response: Response) -> IpResult {
    // 定义用于反序列化 API 响应的结构体
    #[derive(Deserialize, Serialize)]
    struct IpLarkComDigitalElementResp {
        ip: IpAddr,
        country: Option<String>,
        // region: Option<String>,
        city: Option<String>,
        latitude: Option<f64>,
        longitude: Option<f64>,
        asn: Option<u32>,
        asname: Option<String>,
        connection: Option<String>,
        connection_type: Option<String>,

        #[serde(rename = "type")]
        type_str: Option<String>,
        tag: Option<String>,
    }

    // 将响应体解析为 JSON
    let Ok(json) = response.json::<IpLarkComDigitalElementResp>().await else {
        return json_parse_error_ip_result(
            "IpLark.com Digital Element",
            "Unable to parse the returned result into Json",
        );
    };

    // 解析风险标签
    let mut tags = Vec::new();
    if let Some(connection) = json.connection {
        match connection.as_str() {
            "mobile" => tags.push(Mobile),
            _ => tags.push(Other(connection.to_uppercase())),
        }
    }

    if let Some(connection_type) = json.connection_type {
        match connection_type.as_str() {
            "mobile" => tags.push(Mobile),
            _ => tags.push(Other(connection_type.to_uppercase())),
        }
    }

    if let Some(type_str) = json.type_str {
        match type_str.as_str() {
            "hosting" => tags.push(Hosting),
            _ => tags.push(Other(type_str.to_uppercase())),
        }
    }

    if let Some(tag) = json.tag {
        match tag.as_str() {
            "tor-exit" => tags.push(Tor),
            "vpn" => tags.push(Proxy),
            _ => tags.push(Other(tag.to_uppercase())),
        }
    }

    // 对标签进行去重
    let mut seen = HashSet::new();
    for tag in tags {
        seen.insert(tag.clone());
    }
    let result: Vec<_> = seen.into_iter().collect();

    // 构建 IpResult
    IpResult {
        success: true,
        error: No,
        provider: "IpLark.com Digital Element".to_string(),
        ip: Some(json.ip),
        autonomous_system: {
            if let (Some(asn), Some(isp)) = (json.asn, json.asname) {
                Some(AS {
                    number: asn,
                    name: isp,
                })
            } else {
                None
            }
        },
        region: Some(Region {
            country: json.country,
            region: None,
            city: json.city,
            coordinates: if let (Some(lat), Some(lon)) = (json.latitude, json.longitude) {
                Some(Coordinates {
                    latitude: lat.to_string(),
                    longitude: lon.to_string(),
                })
            } else {
                None
            },
            time_zone: None,
        }),
        risk: Some(Risk {
            risk: None,
            tags: Some(result),
        }),
        used_time: None,
    }
}
