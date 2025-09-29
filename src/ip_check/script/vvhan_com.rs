// src/ip_check/script/vvhan_com.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, request_error_ip_result, IpResult, Region,
    AS,
}; // 引入IP检查结果相关的结构体和函数
use crate::ip_check::script::create_reqwest_client; // 引入创建 reqwest 客户端的函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use serde::{Deserialize, Serialize}; // 引入 serde 的 Deserialize 和 Serialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 VvhanCom 结构体
pub struct VvhanCom;

// 定义提供商名称
const PROVIDER_NAME: &str = "Vvhan.com";

// 为 VvhanCom 实现 IpCheck trait
#[async_trait]
impl IpCheck for VvhanCom {
    // 异步检查 IP 地址
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip_addr) = ip {
            // 查询指定 IP
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();

                let client = match create_reqwest_client(None).await {
                    Ok(c) => c,
                    Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                };

                let response = match client
                    .get(format!("https://api.vvhan.com/api/ipInfo?ip={ip_addr}"))
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => return request_error_ip_result(PROVIDER_NAME, &e.to_string()),
                };

                let mut result_without_time = parse_vvhan_com_resp(response).await;
                result_without_time.used_time = Some(time_start.elapsed()); // 记录耗时
                result_without_time
            });

            match handle.await {
                Ok(result) => vec![result],
                Err(_) => vec![request_error_ip_result(
                    PROVIDER_NAME,
                    "Task panicked or was cancelled.",
                )],
            }
        } else {
            // 查询本机 IP (尝试 IPv4 和 IPv6)
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let client_v4 = match create_reqwest_client(Some(false)).await {
                    // 强制使用 IPv4
                    Ok(c) => c,
                    Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                };

                let response = match client_v4
                    .get("https://api.vvhan.com/api/ipInfo")
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => return request_error_ip_result(PROVIDER_NAME, &e.to_string()),
                };

                let mut result_without_time = parse_vvhan_com_resp(response).await;
                result_without_time.used_time = Some(time_start.elapsed());
                result_without_time
            });

            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let client_v6 = match create_reqwest_client(Some(true)).await {
                    // 强制使用 IPv6
                    Ok(c) => c,
                    Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
                };

                let response = match client_v6
                    .get("https://api.vvhan.com/api/ipInfo")
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => return request_error_ip_result(PROVIDER_NAME, &e.to_string()),
                };

                let mut result_without_time = parse_vvhan_com_resp(response).await;
                result_without_time.used_time = Some(time_start.elapsed());
                result_without_time
            });

            let mut results = Vec::new();
            if let Ok(r_v4) = handle_v4.await {
                results.push(r_v4);
            }
            if let Ok(r_v6) = handle_v6.await {
                // 避免在 IPv4 和 IPv6 客户端返回相同成功结果时重复添加
                // (例如，系统只有 IPv4，IPv6 客户端回退并获取了相同数据)
                let mut add_v6 = true;
                if let Some(v4_res) = results.first() {
                    if v4_res.success && r_v6.success && v4_res.ip == r_v6.ip {
                        add_v6 = false;
                    }
                }
                if add_v6 {
                    results.push(r_v6);
                }
            }
            results
        }
    }
}

// 定义用于解析 API info 部分的结构体
#[derive(Deserialize, Serialize, Debug)]
struct VvhanComApiInfoPayload {
    country: String,
    prov: String,
    city: String,
    isp: String,
}

// 定义用于解析 API 顶层响应的结构体
#[derive(Deserialize, Serialize, Debug)]
struct VvhanComApiRespPayload {
    success: bool,
    ip: Option<String>, // API 可能在某些错误情况下不返回 IP，或 IP 格式错误
    info: Option<VvhanComApiInfoPayload>, // info 也可能在错误时缺失
    tip: Option<String>, // 用于捕获如 "您已超过免费使用次数..." 之类的消息
    error: Option<String>, // 用于捕获如 "IP地址格式错误" 之类的消息
}

// 解析 Vvhan.com 的 API 响应
async fn parse_vvhan_com_resp(response: Response) -> IpResult {
    if !response.status().is_success() {
        let err_msg = format!("HTTP Error: {}", response.status());
        return request_error_ip_result(PROVIDER_NAME, &err_msg);
    }

    let response_text = match response.text().await {
        Ok(text) => text,
        Err(e) => {
            return request_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to read response text: {e}"),
            );
        }
    };

    let payload: VvhanComApiRespPayload = match serde_json::from_str(&response_text) {
        Ok(p) => p,
        Err(e) => {
            let snippet = response_text.chars().take(100).collect::<String>(); // 获取部分响应文本用于调试
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse JSON: {e}. Response snippet: '{snippet}'"),
            );
        }
    };

    if !payload.success {
        let mut err_msg = payload
            .tip
            .or(payload.error)
            .unwrap_or_else(|| "API indicated failure without a specific message.".to_string());
        if err_msg.is_empty() {
            // API 可能返回空的错误字段
            err_msg = "API indicated failure.".to_string();
        }

        let mut err_res = request_error_ip_result(PROVIDER_NAME, &err_msg);
        // 即使失败，也尝试解析并包含 IP 地址 (如果 API 返回了的话)
        if let Some(ip_str) = payload.ip.as_deref() {
            err_res.ip = ip_str.parse::<IpAddr>().ok();
        }
        return err_res;
    }

    // 如果 success == true，我们期望 'ip' 和 'info' 字段存在且有效
    let ip_str = match payload.ip {
        Some(s) => s,
        None => {
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                "API success=true but 'ip' field is missing.",
            );
        }
    };

    let parsed_ip = match ip_str.parse::<IpAddr>() {
        Ok(ip_addr) => ip_addr,
        Err(_) => {
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                &format!("Failed to parse IP string from API: '{ip_str}'"),
            );
        }
    };

    let api_info_data = match payload.info {
        Some(info_data) => info_data,
        None => {
            return json_parse_error_ip_result(
                PROVIDER_NAME,
                "API success=true but 'info' field is missing.",
            );
        }
    };

    // 处理 "-", 空字符串, "unknown", "未知" 等表示无效数据的情况
    let process_field = |field_val: String| {
        let lower_val = field_val.to_lowercase();
        if field_val == "-" || field_val.is_empty() || lower_val == "unknown" || field_val == "未知"
        {
            None
        } else {
            Some(field_val)
        }
    };

    let country = process_field(api_info_data.country);
    let prov = process_field(api_info_data.prov);
    let city = process_field(api_info_data.city);
    let isp_name = process_field(api_info_data.isp);

    IpResult {
        success: true,
        error: No,
        provider: PROVIDER_NAME.to_string(),
        ip: Some(parsed_ip),
        autonomous_system: isp_name.map(|name| AS {
            number: 0, // API 不提供 ASN 编号
            name,
        }),
        region: Some(Region {
            country,
            region: prov,
            city,
            coordinates: None, // API 不提供经纬度
            time_zone: None,   // API 不提供时区
        }),
        risk: None,      // API 不提供风险信息
        used_time: None, // 将由调用者设置
    }
}
