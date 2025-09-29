// src/ip_check/script/nameless13_xyz.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::{
    create_reqwest_client_error, not_support_error, request_error_ip_result, IpResult,
}; // 引入IP检查结果相关的结构体和函数
use crate::ip_check::script::create_reqwest_client; // 引入创建 reqwest 客户端的函数
use crate::ip_check::script::ip233_cn::{ip233_style_headers, parse_ip233_style_resp}; // 引入 ip233 风格的请求头和响应解析函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use std::net::IpAddr; // 引入 IpAddr

// 定义 Nameless13Xyz 结构体
pub struct Nameless13Xyz;

// 定义提供商名称
const PROVIDER_NAME: &str = "Nameless13.xyz";
// 定义 IPv4 API URL
const API_URL_V4: &str = "https://ip.nameless13.xyz/ip";
// 定义 IPv6 API URL
const API_URL_V6: &str = "https://ip6.nameless13.xyz/ip";

// 为 Nameless13Xyz 实现 IpCheck trait
#[async_trait]
impl IpCheck for Nameless13Xyz {
    // 异步检查 IP 地址
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            // API 不支持查询指定 IP
            return vec![not_support_error(PROVIDER_NAME)];
        }

        let mut results = Vec::new();

        // --- 检查本机 IPv4 ---
        let handle_v4 = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            let client_v4 = match create_reqwest_client(Some(false)).await {
                Ok(c) => c,
                Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
            };

            let response_result = client_v4
                .get(API_URL_V4)
                .headers(ip233_style_headers().await)
                .send()
                .await;
            let mut result = match response_result {
                Ok(r) => parse_ip233_style_resp(r, PROVIDER_NAME).await,
                Err(e) => request_error_ip_result(PROVIDER_NAME, &format!("IPv4 request: {e}")),
            };
            result.used_time = Some(time_start.elapsed()); // 记录耗时
            result
        });

        // --- 检查本机 IPv6 ---
        let handle_v6 = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            let client_v6 = match create_reqwest_client(Some(true)).await {
                Ok(c) => c,
                Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
            };

            let response_result = client_v6
                .get(API_URL_V6)
                .headers(ip233_style_headers().await)
                .send()
                .await;
            let mut result = match response_result {
                Ok(r) => parse_ip233_style_resp(r, PROVIDER_NAME).await,
                Err(e) => request_error_ip_result(PROVIDER_NAME, &format!("IPv6 request: {e}")),
            };
            result.used_time = Some(time_start.elapsed());
            result
        });

        if let Ok(r) = handle_v4.await {
            results.push(r);
        }
        if let Ok(r) = handle_v6.await {
            // 如果 IPv4 和 IPv6 的结果 IP 相同，则不重复添加
            if !results.iter().any(|res| res.success && res.ip == r.ip) {
                results.push(r);
            }
        }
        results
    }
}
