// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, not_support_error, parse_ip_error_ip_result, request_error_ip_result,
    IpResult, Region,
}; // 引入IP检查结果相关的结构体和函数
use crate::ip_check::script::create_reqwest_client; // 引入创建 reqwest 客户端的函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use serde_json::Value; // 引入 serde_json 的 Value
use std::net::IpAddr; // 引入 IpAddr
use std::str::FromStr; // 引入 FromStr trait

// 定义 IpIpNet 结构体
pub struct IpIpNet;

// 为 IpIpNet 实现 IpCheck trait
#[async_trait]
impl IpCheck for IpIpNet {
    // 异步检查 IP 地址
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        // Ipip.net 不支持查询指定 IP, 只支持查询本机 IP
        if ip.is_some() {
            return vec![not_support_error("Ipip.Net")];
        }

        // 只查询本机的 IPv4 地址
        let handle_v4 = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            // 强制使用IPv4进行API访问
            let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                return create_reqwest_client_error("Ipip.Net");
            };

            let Ok(result) = client_v4.get("https://myip.ipip.net/json").send().await else {
                return request_error_ip_result("Ipip.Net", "Unable to connect");
            };

            let json = if let Ok(json) = result.json::<Value>().await {
                json
            } else {
                return request_error_ip_result("Ipip.Net", "Unable to parse json");
            };

            let mut result_without_time = get_ipip_net_info(json);
            let end_time = time_start.elapsed();
            result_without_time.used_time = Some(end_time); // 记录耗时
            result_without_time
        });

        vec![handle_v4.await.unwrap_or(json_parse_error_ip_result(
            "Ipip.Net",
            "Unable to parse json",
        ))]
    }
}

// 解析 Ipip.net 的 API 响应
fn get_ipip_net_info(json: Value) -> IpResult {
    // 解析 "data" 字段
    let data = if let Some(data) = json.get("data") {
        data
    } else {
        return request_error_ip_result("Ipip.Net", "Unable to parse json");
    };

    // 解析 IP 地址
    let ip = if let Some(ip) = data.get("ip") {
        if let Some(ip) = ip.as_str() {
            if let Ok(ip) = IpAddr::from_str(ip) {
                ip
            } else {
                return parse_ip_error_ip_result("Ipip.Net", "Unable to parse ip");
            }
        } else {
            return parse_ip_error_ip_result("Ipip.Net", "Unable to parse ip");
        }
    } else {
        return parse_ip_error_ip_result("Ipip.Net", "Unable to parse ip");
    };

    // 解析地理位置信息 (数组形式)
    let location = if let Some(location) = data.get("location") {
        if let Some(location) = location.as_array() {
            location
        } else {
            return parse_ip_error_ip_result("Ipip.Net", "Unable to parse location");
        }
    } else {
        return parse_ip_error_ip_result("Ipip.Net", "Unable to parse location");
    };

    // 解析国家
    let country = if let Some(country) = location.first() {
        country.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    // 解析地区
    let region = if let Some(region) = location.get(1) {
        region.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    // 解析城市
    let city = if let Some(city) = location.get(2) {
        city.as_str().map(std::string::ToString::to_string)
    } else {
        None
    };

    // 构建并返回 IpResult
    IpResult {
        success: true,
        error: No,
        provider: "Ipip.Net".to_string(),
        ip: Some(ip),
        autonomous_system: None, // API不提供ASN信息
        region: Some(Region {
            country,
            region,
            city,
            coordinates: None, // API不提供坐标信息
            time_zone: None,   // API不提供时区信息
        }),
        risk: None, // API不提供风险信息
        used_time: None, // 耗时将在调用处设置
    }
}
