// src/ip_check/script/cloudflare.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, not_support_error, parse_ip_error_ip_result, request_error_ip_result,
    IpResult,
}; // 引入错误处理函数和结果结构体
use crate::ip_check::script::create_reqwest_client; // 引入 reqwest 客户端创建函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr}; // 引入 IP 地址相关的结构体
use std::str::FromStr; // 引入 FromStr trait

// 定义 Cloudflare 结构体
pub struct Cloudflare;

// 为 Cloudflare 实现 IpCheck trait
#[async_trait]
impl IpCheck for Cloudflare {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            // 此 API 不支持查询指定 IP
            vec![not_support_error("Cloudflare")]
        } else {
            // 异步查询 IPv4 地址
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();

                // 创建仅使用 IPv4 的 reqwest 客户端
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("Cloudflare");
                };

                // 发送 GET 请求
                let Ok(result) = client_v4
                    .get("https://cloudflare.com/cdn-cgi/trace")
                    .send()
                    .await
                else {
                    return request_error_ip_result("Cloudflare", "Unable to connect");
                };

                // 解析响应并计算耗时
                let mut result_without_time = get_cloudflare_info(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            // 异步查询 IPv6 地址
            let handle_v6 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();

                // 创建仅使用 IPv6 的 reqwest 客户端
                let Ok(client_v6) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error("Cloudflare");
                };

                // 发送 GET 请求
                let Ok(result) = client_v6
                    .get("https://cloudflare.com/cdn-cgi/trace")
                    .send()
                    .await
                else {
                    return request_error_ip_result("Cloudflare", "Unable to connect");
                };

                // 解析响应并计算耗时
                let mut result_without_time = get_cloudflare_info(result).await;
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

// 解析 Cloudflare 的响应
async fn get_cloudflare_info(response: Response) -> IpResult {
    if !response.status().is_success() {
        return request_error_ip_result("Cloudflare", "Unable to connect");
    }
    // 将响应体解析为文本
    let Ok(html) = response.text().await else {
        return parse_ip_error_ip_result("Cloudflare", "Unable to parse html");
    };

    // 从文本中提取 IP 地址
    let mut ip = String::new();
    for line in html.lines() {
        if line.starts_with("ip=") {
            ip = line.split('=').collect::<Vec<&str>>()[1].to_string();
            break;
        }
    }

    // 将字符串解析为 IpAddr
    let ip = match Ipv4Addr::from_str(ip.as_str()) {
        Ok(ip) => IpAddr::V4(ip),
        Err(_) => match Ipv6Addr::from_str(ip.as_str()) {
            Ok(ip) => IpAddr::V6(ip),
            Err(_) => {
                return parse_ip_error_ip_result("Cloudflare", "Unable to parse ip");
            }
        },
    };
    // 构建 IpResult
    IpResult {
        success: true,
        error: No,
        provider: "Cloudflare".to_string(),
        ip: Some(ip),
        autonomous_system: None,
        region: None,
        risk: None,
        used_time: None,
    }
}
