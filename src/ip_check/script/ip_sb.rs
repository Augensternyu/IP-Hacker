// src/ip_check/script/ip_sb.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, parse_ip_error_ip_result, request_error_ip_result, Coordinates, IpResult,
    Region, AS,
}; // 引入错误处理函数和结果结构体
use crate::ip_check::script::create_reqwest_client; // 引入 reqwest 客户端创建函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::{header, Response}; // 引入 reqwest 的 header 和 Response
use std::net::IpAddr; // 引入 IpAddr
use std::str::FromStr; // 引入 FromStr trait

// 定义 IpSb 结构体
pub struct IpSb;

// 为 IpSb 实现 IpCheck trait
#[async_trait]
impl IpCheck for IpSb {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            // 如果指定了 IP 地址
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // 创建 reqwest 客户端
                let Ok(client_v4) = create_reqwest_client(None).await else {
                    return create_reqwest_client_error("IP.sb");
                };

                // 发送 GET 请求
                let Ok(result) = client_v4
                    .get(format!("https://api.ip.sb/geoip/{ip}"))
                    .headers(headers())
                    .send()
                    .await
                else {
                    return request_error_ip_result("IP.sb", "Unable to connect");
                };

                // 解析响应并计算耗时
                let mut result_without_time = get_ip_sb_info(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            // 等待并收集结果
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
                    return create_reqwest_client_error("IP.sb");
                };

                // 发送 GET 请求
                let Ok(result) = client_v4
                    .get("https://api.ip.sb/geoip/")
                    .headers(headers())
                    .send()
                    .await
                else {
                    return request_error_ip_result("IP.sb", "Unable to connect");
                };

                // 解析响应并计算耗时
                let mut result_without_time = get_ip_sb_info(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // 创建仅使用 IPv6 的 reqwest 客户端
                let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error("IP.sb");
                };

                // 发送 GET 请求
                let Ok(result) = client_v6
                    .get("https://api.ip.sb/geoip/")
                    .headers(headers())
                    .send()
                    .await
                else {
                    return request_error_ip_result("IP.sb", "Unable to connect");
                };

                // 解析响应并计算耗时
                let mut result_without_time = get_ip_sb_info(result).await;
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

// 解析 IP.sb 的 API 响应
async fn get_ip_sb_info(response: Response) -> IpResult {
    if !response.status().is_success() {
        return request_error_ip_result("IP.sb", "Unable to connect");
    }

    // 将响应体解析为 JSON
    let json: serde_json::Value = match response.json().await {
        Ok(p) => p,
        Err(_) => {
            return request_error_ip_result("IP.sb", "Unable to parse the returned result into Json");
        }
    };

    // 从 JSON 中提取 IP 地址
    let ip = if let Some(ip) = json.get("ip") {
        if let Some(ip) = ip.as_str() {
            match IpAddr::from_str(ip) {
                Ok(ip) => ip,
                Err(_) => {
                    return parse_ip_error_ip_result(
                        "IP.sb",
                        "Unable to parse the returned result into Json",
                    );
                }
            }
        } else {
            return json_parse_error_ip_result("IP.sb", "Unable to get value for `ip`");
        }
    } else {
        return json_parse_error_ip_result("IP.sb", "Unable to get value for `ip`");
    };

    // 从 JSON 中提取国家信息
    let country = if let Some(country) = json.get("country") {
        country.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    // 从 JSON 中提取区域信息
    let province = if let Some(region) = json.get("region") {
        region.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    // 从 JSON 中提取城市信息
    let city = if let Some(city) = json.get("city") {
        city.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    // 从 JSON 中提取 ASN
    let asn = if let Some(asn) = json.get("asn") {
        asn.as_u64()
    } else {
        None
    };

    // 从 JSON 中提取组织信息
    let org = if let Some(org) = json.get("asn_organization") {
        org.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    // 从 JSON 中提取纬度信息
    let lat = if let Some(lat) = json.get("latitude") {
        lat.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    // 从 JSON 中提取经度信息
    let lon = if let Some(lon) = json.get("longitude") {
        lon.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    // 从 JSON 中提取时区信息
    let timezone = if let Some(timezone) = json.get("timezone") {
        timezone.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    // 构建 IpResult
    IpResult {
        success: true,
        error: No,
        provider: "IP.sb".to_string(),
        ip: Some(ip),
        autonomous_system: {
            if let (Some(asn), Some(org)) = (asn, org) {
                Some(AS {
                    number: u32::try_from(asn).unwrap_or(0),
                    name: org,
                })
            } else {
                None
            }
        },
        region: Some(Region {
            country,
            province,
            city,
            coordinates: {
                if let (Some(latitude), Some(longitude)) = (lat, lon) {
                    Some(Coordinates { latitude, longitude })
                } else {
                    None
                }
            },
            time_zone: timezone,
        }),
        risk: None,
        used_time: None,
    }
}

// 构建请求头
fn headers() -> header::HeaderMap {
    let mut headers = header::HeaderMap::new();
    headers.insert("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".parse().unwrap());
    headers.insert("accept-language", "zh-CN,zh;q=0.9".parse().unwrap());
    headers.insert("cache-control", "max-age=0".parse().unwrap());
    headers.insert("dnt", "1".parse().unwrap());
    headers.insert("priority", "u=0, i".parse().unwrap());
    headers.insert(
        "sec-ch-ua",
        "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\""
            .parse()
            .unwrap(),
    );
    headers.insert("sec-ch-ua-mobile", "?0".parse().unwrap());
    headers.insert("sec-ch-ua-platform", "\"Linux\"".parse().unwrap());
    headers.insert("sec-fetch-dest", "document".parse().unwrap());
    headers.insert("sec-fetch-mode", "navigate".parse().unwrap());
    headers.insert("sec-fetch-site", "none".parse().unwrap());
    headers.insert("sec-fetch-user", "?1".parse().unwrap());
    headers.insert("upgrade-insecure-requests", "1".parse().unwrap());
    headers.insert("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".parse().unwrap());

    headers
}
