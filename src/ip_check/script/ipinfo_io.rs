// 引入项目内的模块和外部库
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, parse_ip_error_ip_result, request_error_ip_result, Coordinates, IpCheckError,
    IpResult, Region, AS,
}; // 引入IP检查结果相关的结构体和函数
use crate::ip_check::script::create_reqwest_client; // 引入创建 reqwest 客户端的函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use regex::Regex; // 引入 regex 用于正则表达式
use serde_json::Value; // 引入 serde_json 的 Value
use std::net::IpAddr; // 引入 IpAddr
use std::str::FromStr; // 引入 FromStr trait

// 定义 IpInfoIo 结构体
pub struct IpInfoIo;

// 为 IpInfoIo 实现 IpCheck trait
#[async_trait]
impl IpCheck for IpInfoIo {
    // 异步检查 IP 地址
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            // --- 检查指定IP ---
            let time_start = tokio::time::Instant::now();
            // 强制使用IPv4进行API访问
            let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                return vec![create_reqwest_client_error("Ipinfo.io")];
            };

            let res = if let Ok(res) = client_v4
                .get(format!("https://ipinfo.io/{ip}"))
                .send()
                .await
            {
                res
            } else {
                return vec![request_error_ip_result("Ipinfo.io", "Unable to connect")];
            };

            if res.status() == 200 {
                let json = if let Ok(json) = res.json::<Value>().await {
                    json
                } else {
                    return vec![parse_ip_error_ip_result(
                        "Ipinfo.io",
                        "Unable to parse json",
                    )];
                };

                vec![{
                    let mut result_without_time = get_ipinfo_io(json);
                    let end_time = time_start.elapsed();
                    result_without_time.used_time = Some(end_time); // 记录耗时
                    result_without_time
                }]
            } else {
                vec![request_error_ip_result(
                    "Ipinfo.io",
                    "Server returned an error",
                )]
            }
        } else {
            // --- 检查本机IP (v4 和 v6) ---
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("Ipinfo.io");
                };

                let Ok(result) = client_v4.get("https://ipinfo.io").send().await else {
                    return request_error_ip_result("Ipinfo.io", "Unable to connect");
                };

                if result.status() == 200 {
                    let json = if let Ok(json) = result.json::<Value>().await {
                        json
                    } else {
                        return parse_ip_error_ip_result("Ipinfo.io", "Unable to parse json");
                    };
                    let mut result_without_time = get_ipinfo_io(json);
                    let end_time = time_start.elapsed();
                    result_without_time.used_time = Some(end_time);
                    result_without_time
                } else {
                    request_error_ip_result("Ipinfo.io", "ipinfo.io returned an error")
                }
            });

            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error("Ipinfo.io");
                };

                let Ok(result) = client_v6.get("https://v6.ipinfo.io").send().await else {
                    return request_error_ip_result("Ipinfo.io", "Unable to connect");
                };

                if result.status() == 200 {
                    let json = if let Ok(json) = result.json::<Value>().await {
                        json
                    } else {
                        return parse_ip_error_ip_result("Ipinfo.io", "Unable to parse json");
                    };
                    let mut result_without_time = get_ipinfo_io(json);
                    let end_time = time_start.elapsed();
                    result_without_time.used_time = Some(end_time);
                    result_without_time
                } else {
                    request_error_ip_result("Ipinfo.io", "ipinfo.io returned an error")
                }
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

// 解析 Ipinfo.io 的 API 响应
fn get_ipinfo_io(ip: Value) -> IpResult {
    // 解析国家
    let country = if let Some(country) = ip.get("country") {
        country.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    // 解析地区
    let region = if let Some(region) = ip.get("region") {
        region.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    // 解析城市
    let city = if let Some(city) = ip.get("city") {
        city.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    // 解析组织信息字符串
    let org_str = if let Some(org) = ip.get("org") {
        org.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    // 使用正则表达式从组织信息中提取 ASN 和组织名称
    let re = Regex::new(r"^(AS\d+)\s+(.*)$").unwrap();
    let Some((asn, org)) = (if let Some(org_str) = org_str {
        let caps = re.captures(&org_str);
        if let Some(caps) = caps {
            let asn = caps.get(1).unwrap().as_str().to_string();
            let org = caps.get(2).unwrap().as_str().to_string();
            Some((asn, org))
        } else {
            None
        }
    } else {
        None
    }) else {
        return json_parse_error_ip_result("Ipinfo.io", "Unable to parse json");
    };

    // 解析 ASN 编号
    let asn = asn.replace("AS", "").parse::<u32>().unwrap_or(0);

    // 解析地理位置坐标
    let loc = if let Some(loc) = ip.get("loc") {
        loc.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    let temp = loc.unwrap_or(String::new());
    let (latitude, longitude) = temp.split_once(',').unwrap();

    // 解析时区
    let time_zone = if let Some(time_zone) = ip.get("timezone") {
        time_zone.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    // 构建并返回 IpResult
    IpResult {
        success: true,
        error: IpCheckError::No,
        provider: "Ipinfo.io".to_string(),
        ip: Some(IpAddr::from_str(ip["ip"].as_str().unwrap()).unwrap()),
        autonomous_system: Some(AS {
            number: asn,
            name: org,
        }),
        region: Some(Region {
            country,
            region,
            city,
            coordinates: Some(Coordinates {
                latitude: latitude.to_string(),
                longitude: longitude.to_string(),
            }),
            time_zone,
        }),
        risk: None, // API不提供风险信息
        used_time: None, // 耗时将在调用处设置
    }
}
