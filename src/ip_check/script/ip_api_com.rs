// src/ip_check/script/ip_api_com.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::RiskTag::{Mobile, Proxy}; // 引入风险标签
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, request_error_ip_result, Coordinates, IpResult, Region,
    Risk, AS,
}; // 引入错误处理函数和结果结构体
use crate::ip_check::script::create_reqwest_client; // 引入 reqwest 客户端创建函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use serde::{Deserialize, Serialize}; // 引入 serde 的 Deserialize 和 Serialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 IpApiCom 结构体
pub struct IpApiCom;

// 为 IpApiCom 实现 IpCheck trait
#[async_trait]
impl IpCheck for IpApiCom {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            // 如果指定了 IP 地址
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();

                // 创建 reqwest 客户端
                let Ok(client) = create_reqwest_client(None).await else {
                    return create_reqwest_client_error("Ip-Api.com");
                };

                // 发送 GET 请求
                let Ok(result) = client
                    .get(format!("https://pro.ip-api.com/json/{ip}?fields=66846719&key=EEKS6bLi6D91G1p&lang=en-US"))
                    .send()
                    .await
                else {
                    return request_error_ip_result("Ip-Api.com", "Unable to connect");
                };

                // 解析响应并计算耗时
                let mut result_without_time = get_ip_api_com_info(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            vec![handle.await.unwrap_or(json_parse_error_ip_result(
                "Ip-Api.com",
                "Unable to parse json",
            ))]
        } else {
            // 如果未指定 IP 地址，则查询本机 IP
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();

                // 创建仅使用 IPv4 的 reqwest 客户端
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("Ip-Api.com");
                };

                // 发送 GET 请求
                let Ok(result) = client_v4
                    .get("https://pro.ip-api.com/json/?fields=66846719&key=EEKS6bLi6D91G1p")
                    .send()
                    .await
                else {
                    return request_error_ip_result("Ip-Api.com", "Unable to connect");
                };

                // 解析响应并计算耗时
                let mut result_without_time = get_ip_api_com_info(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            vec![handle_v4.await.unwrap_or(json_parse_error_ip_result(
                "Ip-Api.com",
                "Unable to parse json",
            ))]
        }
    }
}

// 解析 Ip-Api.com 的 API 响应
async fn get_ip_api_com_info(resp: Response) -> IpResult {
    // 定义用于反序列化 API 响应的结构体
    #[derive(Deserialize, Serialize)]
    struct IpApiComResp {
        status: String,
        country: Option<String>,

        #[serde(rename = "regionName")]
        region_name: Option<String>,

        city: Option<String>,
        lat: Option<f64>,
        lon: Option<f64>,
        timezone: Option<String>,
        isp: Option<String>,

        #[serde(rename = "as")]
        asn: Option<String>,

        #[serde(rename = "query")]
        ip: Option<IpAddr>,

        proxy: bool,
        hosting: bool,
        mobile: bool,
    }

    // 将响应体解析为 JSON
    let Ok(json) = resp.json::<IpApiComResp>().await else {
        return json_parse_error_ip_result(
            "Ip-Api.com",
            "Unable to parse the returned result into Json",
        );
    };

    // 检查 API 返回的状态
    if json.status != "success" {
        return request_error_ip_result("Ip-Api.com", "Unable to get Ip API info");
    }

    // 解析 ASN
    let asn = if let Some(asn) = json.asn {
        let asn = asn.split(' ').collect::<Vec<&str>>()[0];
        Some(asn.replace("AS", "").parse::<u32>().unwrap_or(0))
    } else {
        None
    };

    // 构建 IpResult
    IpResult {
        success: true,
        error: No,
        provider: "Ip-Api.com".to_string(),
        ip: json.ip,
        autonomous_system: {
            if let (Some(asn), Some(isp)) = (asn, json.isp) {
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
            region: json.region_name,
            city: json.city,
            coordinates: {
                if let (Some(lat), Some(lon)) = (json.lat, json.lon) {
                    Some(Coordinates {
                        lat: lat.to_string(),
                        lon: lon.to_string(),
                    })
                } else {
                    None
                }
            },
            time_zone: json.timezone,
        }),
        risk: {
            let mut tags = vec![];
            if json.proxy {
                tags.push(Proxy);
            }
            if json.mobile {
                tags.push(Mobile);
            }
            if json.hosting {
                tags.push(Mobile); // 注意：这里原文将 hosting 也标记为 Mobile，可能是一个笔误
            }
            Some(Risk {
                risk: None,
                tags: Some(tags),
            })
        },
        used_time: None,
    }
}
