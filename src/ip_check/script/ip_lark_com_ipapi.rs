// src/ip_check/script/ip_lark_com_ipapi.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::RiskTag::{Hosting, Mobile, Proxy}; // 引入风险标签
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, not_support_error, request_error_ip_result, Coordinates, IpResult,
    Region, Risk, AS,
}; // 引入错误处理函数和结果结构体
use crate::ip_check::script::create_reqwest_client; // 引入 reqwest 客户端创建函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use serde::{Deserialize, Serialize}; // 引入 serde 的 Deserialize 和 Serialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 IpLarkComIpApi 结构体
pub struct IpLarkComIpApi;

// 为 IpLarkComIpApi 实现 IpCheck trait
#[async_trait]
impl IpCheck for IpLarkComIpApi {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            // 此 API 不支持查询指定 IP
            vec![not_support_error("IpLark.com IpApi")]
        } else {
            // 异步查询 IPv4 地址
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // 创建仅使用 IPv4 的 reqwest 客户端
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("IpLark.com IpApi");
                };

                // 发送 GET 请求
                let Ok(result) = client_v4
                    .get("https://iplark.com/ipapi/public/ipinfo?db=ipapi")
                    .send()
                    .await
                else {
                    return request_error_ip_result("IpLark.com IpApi", "Unable to connect");
                };

                // 解析响应并计算耗时
                let mut result_without_time = parse_ip_lark_com_ipapi(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            // 异步查询 IPv6 地址
            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // 创建仅使用 IPv6 的 reqwest 客户端
                let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error("IpLark.com IpApi");
                };

                // 发送 GET 请求
                let Ok(result) = client_v6
                    .get("https://6.iplark.com/ipapi/public/ipinfo?db=ipapi")
                    .send()
                    .await
                else {
                    return request_error_ip_result("IpLark.com IpApi", "Unable to connect");
                };

                // 解析响应并计算耗时
                let mut result_without_time = parse_ip_lark_com_ipapi(result).await;
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

// 解析 IpLark.com IpApi 的 API 响应
async fn parse_ip_lark_com_ipapi(response: Response) -> IpResult {
    // 定义用于反序列化 API 响应的结构体
    #[derive(Deserialize, Serialize)]
    struct IpLarkComIpApiResp {
        #[serde(rename = "as")]
        asn: Option<String>,
        city: Option<String>,
        country: Option<String>,

        #[serde(rename = "regionName")]
        region_name: Option<String>,

        timezone: Option<String>,
        query: IpAddr,
        isp: Option<String>,
        lat: Option<f64>,
        lon: Option<f64>,

        hosting: Option<bool>,
        proxy: Option<bool>,
        mobile: Option<bool>,
    }

    // 将响应体解析为 JSON
    let Ok(json) = response.json::<IpLarkComIpApiResp>().await else {
        return json_parse_error_ip_result(
            "IpLark.com IpApi",
            "Unable to parse the returned result into Json",
        );
    };

    // 解析风险标签
    let mut risk_tags = Vec::new();
    if let Some(true) = json.hosting {
        risk_tags.push(Hosting);
    }
    if let Some(true) = json.proxy {
        risk_tags.push(Proxy);
    }
    if let Some(true) = json.mobile {
        risk_tags.push(Mobile);
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
        provider: "IpLark.com IpApi".to_string(),
        ip: Some(json.query),
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
            coordinates: if let (Some(lat), Some(lon)) = (json.lat, json.lon) {
                Some(Coordinates {
                    latitude: lat.to_string(),
                    longitude: lon.to_string(),
                })
            } else {
                None
            },
            time_zone: json.timezone,
        }),
        risk: Some(Risk {
            risk: None,
            tags: Some(risk_tags),
        }),
        used_time: None,
    }
}
