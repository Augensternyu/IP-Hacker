// src/ip_check/script/ip_checking.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, parse_ip_error_ip_result, request_error_ip_result, Coordinates, IpResult,
    Region, AS,
}; // 引入错误处理函数和结果结构体
use crate::ip_check::script::create_reqwest_client; // 引入 reqwest 客户端创建函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use serde::{Deserialize, Serialize}; // 引入 serde 的 Deserialize 和 Serialize
use std::net::IpAddr; // 引入 IpAddr
use std::str::FromStr; // 引入 FromStr trait

// 定义 IpChecking 结构体
pub struct IpChecking;

// 为 IpChecking 实现 IpCheck trait
#[async_trait]
impl IpCheck for IpChecking {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            // 如果指定了 IP 地址
            vec![{
                let time_start = tokio::time::Instant::now();
                let mut result_without_time = get_ipcheck_ing_info(ip).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            }]
        } else {
            // 如果未指定 IP 地址，则查询本机 IP
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();

                // 创建仅使用 IPv4 的 reqwest 客户端
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("IpCheck.ing");
                };

                // 发送 GET 请求获取 IPv4 地址
                let Ok(result) = client_v4.get("https://4.ipcheck.ing/").send().await else {
                    return request_error_ip_result("IpCheck.ing", "Unable to connect");
                };

                // 解析响应文本
                let Ok(text) = result.text().await else {
                    return parse_ip_error_ip_result("IpCheck.ing", "Unable to parse html");
                };

                let text = text.trim();

                // 将文本解析为 IP 地址
                let Ok(ip) = IpAddr::from_str(text) else {
                    return parse_ip_error_ip_result("IpCheck.ing", text);
                };

                // 获取该 IP 的详细信息
                let mut result_without_time = get_ipcheck_ing_info(ip).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();

                // 创建仅使用 IPv6 的 reqwest 客户端
                let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error("IpCheck.ing");
                };

                // 发送 GET 请求获取 IPv6 地址
                let Ok(result) = client_v6.get("https://6.ipcheck.ing/").send().await else {
                    return request_error_ip_result("IpCheck.ing", "Unable to connect");
                };

                // 解析响应文本
                let Ok(text) = result.text().await else {
                    return parse_ip_error_ip_result("IpCheck.ing", "Unable to parse html");
                };

                let text = text.trim();

                // 将文本解析为 IP 地址
                let Ok(ip) = IpAddr::from_str(text) else {
                    return parse_ip_error_ip_result("IpCheck.ing", text);
                };

                // 获取该 IP 的详细信息
                let mut result_without_time = get_ipcheck_ing_info(ip).await;
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

// 定义用于反序列化 API 响应的结构体
#[derive(Deserialize, Serialize)]
struct IpCheckingResp {
    ip: IpAddr,
    city: Option<String>,
    country_name: Option<String>,
    region: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    asn: Option<String>,
    org: Option<String>,
}

// 获取 IpCheck.ing 的 IP 地理位置信息
async fn get_ipcheck_ing_info(ip: IpAddr) -> IpResult {
    // 创建 reqwest 客户端
    let Ok(client) = create_reqwest_client(None).await else {
        return create_reqwest_client_error("IpCheck.ing");
    };

    // 设置请求头
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("referer", "https://ipcheck.ing/".parse().unwrap());
    headers.insert("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".parse().unwrap());
    headers.insert("content-type", "application/json".parse().unwrap());

    // 发送 GET 请求
    let Ok(res) = client
        .get(format!(
            "https://ipcheck.ing/api/ipchecking?ip={ip}&lang=en"
        ))
        .headers(headers)
        .send()
        .await
    else {
        return request_error_ip_result("IpCheck.ing", "Unable to connect");
    };

    // 将响应体解析为 JSON
    let Ok(json) = res.json::<IpCheckingResp>().await else {
        return crate::ip_check::ip_result::json_parse_error_ip_result(
            "IpCheck.ing",
            "Unable to parse the returned result into Json",
        );
    };

    // 解析 ASN
    let asn = json
        .asn
        .as_ref()
        .map(|asn| asn.replace("AS", "").trim().parse::<u32>().unwrap_or(0));

    // 构建 IpResult
    IpResult {
        success: true,
        error: No,
        provider: "IpCheck.ing".to_string(),
        ip: Some(ip),
        autonomous_system: {
            if let (Some(asn), Some(isp)) = (asn, json.org) {
                Some(AS {
                    number: asn,
                    name: isp,
                })
            } else {
                None
            }
        },
        region: Some(Region {
            country: json.country_name,
            province: json.region,
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
        risk: None,
        used_time: None,
    }
}
