// src/ip_check/script/ip234_in.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, request_error_ip_result, Coordinates, IpResult, Region,
    Risk, AS,
}; // 引入错误处理函数和结果结构体
use crate::ip_check::script::create_reqwest_client; // 引入 reqwest 客户端创建函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use serde::{Deserialize, Serialize}; // 引入 serde 的 Deserialize 和 Serialize
use serde_json::Value; // 引入 serde_json 的 Value 类型，用于处理不确定的 JSON 字段类型
use std::net::IpAddr; // 引入 IpAddr

// 定义 Ip234In 结构体
pub struct Ip234In;

// 为 Ip234In 实现 IpCheck trait
#[async_trait]
impl IpCheck for Ip234In {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            // 如果指定了 IP 地址
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // 创建 reqwest 客户端
                let Ok(client) = create_reqwest_client(None).await else {
                    return create_reqwest_client_error("Ip234.in");
                };

                // 获取地理位置信息
                let Ok(geo_resp) = client
                    .get(format!("https://ip234.in/search_ip?ip={ip}"))
                    .send()
                    .await
                else {
                    return request_error_ip_result("Ip234.in", "Unable to connect for geo info");
                };

                let mut ip_result = parse_ip234_in_search_resp(geo_resp).await;
                if !ip_result.success {
                    return ip_result;
                }

                // 获取欺诈风险评分
                let Ok(fraud_resp) = client
                    .get(format!("https://ip234.in/fraud_check?ip={ip}"))
                    .send()
                    .await
                else {
                    ip_result.used_time = Some(time_start.elapsed());
                    return ip_result;
                };

                if let Some(score) = parse_ip234_in_fraud_resp(fraud_resp).await {
                    ip_result.risk = Some(Risk {
                        risk: Some(score),
                        tags: None,
                    });
                }

                ip_result.used_time = Some(time_start.elapsed());
                ip_result
            });
            vec![handle.await.unwrap()]
        } else {
            // 如果未指定 IP 地址，则查询本机 IP (仅支持 IPv4)
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // 创建仅使用 IPv4 的 reqwest 客户端
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("Ip234.in");
                };

                // 获取本机 IP 及地理位置信息
                let Ok(local_resp) = client_v4.get("https://ip234.in/ip.json").send().await else {
                    return request_error_ip_result("Ip234.in", "Unable to connect for local IP");
                };

                let (mut ip_result, ip_addr_option) = parse_ip234_in_local_resp(local_resp).await;
                if !ip_result.success {
                    return ip_result;
                }

                // 如果成功获取到本机 IP，则查询其欺诈风险评分
                if let Some(ip_addr) = ip_addr_option {
                    let Ok(fraud_resp) = client_v4
                        .get(format!("https://ip234.in/fraud_check?ip={ip_addr}"))
                        .send()
                        .await
                    else {
                        ip_result.used_time = Some(time_start.elapsed());
                        return ip_result;
                    };

                    if let Some(score) = parse_ip234_in_fraud_resp(fraud_resp).await {
                        ip_result.risk = Some(Risk {
                            risk: Some(score),
                            tags: None,
                        });
                    }
                }

                ip_result.used_time = Some(time_start.elapsed());
                ip_result
            });

            let mut results = Vec::new();
            if let Ok(result) = handle_v4.await {
                results.push(result);
            }
            results
        }
    }
}

// 解析 IP 搜索结果的 API 响应
async fn parse_ip234_in_search_resp(response: Response) -> IpResult {
    // 定义用于反序列化搜索结果的结构体
    #[derive(Deserialize, Serialize)]
    struct SearchResp {
        code: i32,
        data: Option<Data>,
        msg: Option<String>,
    }
    #[derive(Deserialize, Serialize)]
    #[serde(rename_all = "snake_case")] // 自动将驼峰命名的 JSON 字段映射到蛇形命名的结构体字段
    struct Data {
        ip: Option<IpAddr>,
        city: Option<String>,
        organization: Option<String>,
        asn: Option<u32>,
        country: Option<String>,
        latitude: Option<Value>, // 使用 Value 类型接收，因为可能是字符串或数字
        longitude: Option<Value>,
        timezone: Option<String>,
        region: Option<String>,
    }

    // 将响应体解析为 JSON
    let Ok(json) = response.json::<SearchResp>().await else {
        return json_parse_error_ip_result("Ip234.in", "Unable to parse search result into Json");
    };

    // 检查 API 返回的状态码
    if json.code != 0 {
        let err_msg = json
            .msg
            .unwrap_or_else(|| "Server returned an error".to_string());
        return json_parse_error_ip_result("Ip234.in", &err_msg);
    }

    // 确保 data 字段存在
    let Some(data) = json.data else {
        return json_parse_error_ip_result(
            "Ip234.in",
            "Server returned success code but no data payload",
        );
    };

    // 手动处理经纬度，因为其类型不确定
    let lat_str = data.latitude.and_then(|v| {
        v.as_str()
            .map(ToString::to_string)
            .or_else(|| v.as_f64().map(|f| f.to_string()))
    });
    let lon_str = data.longitude.and_then(|v| {
        v.as_str()
            .map(ToString::to_string)
            .or_else(|| v.as_f64().map(|f| f.to_string()))
    });

    // 构建 IpResult
    IpResult {
        success: true,
        error: No,
        provider: "Ip234.in".to_string(),
        ip: data.ip,
        autonomous_system: {
            if let (Some(asn), Some(org)) = (data.asn, data.organization) {
                Some(AS {
                    number: asn,
                    name: org,
                })
            } else {
                None
            }
        },
        region: Some(Region {
            country: data.country,
            region: data.region,
            city: data.city,
            coordinates: if let (Some(lat), Some(lon)) = (lat_str, lon_str) {
                Some(Coordinates {
                    latitude: lat,
                    longitude: lon,
                })
            } else {
                None
            },
            time_zone: data.timezone,
        }),
        risk: None,
        used_time: None,
    }
}

// 解析本机 IP 查询结果的 API 响应
async fn parse_ip234_in_local_resp(response: Response) -> (IpResult, Option<IpAddr>) {
    // 定义用于反序列化本机 IP 查询结果的结构体
    #[derive(Deserialize, Serialize)]
    struct LocalResp {
        ip: Option<IpAddr>,
        city: Option<String>,
        organization: Option<String>,
        asn: Option<u32>,
        country: Option<String>,
        latitude: Option<Value>, // 同样使用 Value 类型处理不确定的经纬度类型
        longitude: Option<Value>,
        timezone: Option<String>,
        region: Option<String>,
    }

    // 将响应体解析为 JSON
    let Ok(json) = response.json::<LocalResp>().await else {
        return (
            json_parse_error_ip_result("Ip234.in", "Unable to parse local result into Json"),
            None,
        );
    };

    // 手动处理经纬度
    let lat_str = json.latitude.and_then(|v| {
        v.as_str()
            .map(ToString::to_string)
            .or_else(|| v.as_f64().map(|f| f.to_string()))
    });
    let lon_str = json.longitude.and_then(|v| {
        v.as_str()
            .map(ToString::to_string)
            .or_else(|| v.as_f64().map(|f| f.to_string()))
    });

    let ip_addr = json.ip;
    // 构建 IpResult
    let result = IpResult {
        success: true,
        error: No,
        provider: "Ip234.in".to_string(),
        ip: json.ip,
        autonomous_system: {
            if let (Some(asn), Some(org)) = (json.asn, json.organization) {
                Some(AS {
                    number: asn,
                    name: org,
                })
            } else {
                None
            }
        },
        region: Some(Region {
            country: json.country,
            region: json.region,
            city: json.city,
            coordinates: if let (Some(lat), Some(lon)) = (lat_str, lon_str) {
                Some(Coordinates {
                    latitude: lat,
                    longitude: lon,
                })
            } else {
                None
            },
            time_zone: json.timezone,
        }),
        risk: None,
        used_time: None,
    };
    (result, ip_addr)
}

// 解析欺诈风险评分的 API 响应
async fn parse_ip234_in_fraud_resp(response: Response) -> Option<u16> {
    // 定义用于反序列化欺诈风险评分结果的结构体
    #[derive(Deserialize, Serialize)]
    struct FraudResp {
        code: i32,
        data: Option<Data>,
    }
    #[derive(Deserialize, Serialize)]
    struct Data {
        score: Option<u16>,
    }

    // 将响应体解析为 JSON
    let Ok(json) = response.json::<FraudResp>().await else {
        return None;
    };

    // 检查 API 返回的状态码
    if json.code != 0 {
        return None;
    }

    // 返回评分
    json.data.and_then(|d| d.score)
}
