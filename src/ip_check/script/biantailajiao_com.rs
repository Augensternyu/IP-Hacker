// src/ip_check/script/biantailajiao_com.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::{
    create_reqwest_client_error, not_support_error, request_error_ip_result, IpResult,
}; // 引入错误处理函数和结果结构体
use crate::ip_check::script::create_reqwest_client; // 引入 reqwest 客户端创建函数
use crate::ip_check::script::ip233_cn::{ip233_style_headers, parse_ip233_style_resp}; // 引入 ip233 风格的头文件和响应解析函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use std::net::IpAddr; // 引入 IpAddr

// 定义 BiantailajiaoCom 结构体
pub struct BiantailajiaoCom;

// 定义常量
const PROVIDER_NAME: &str = "Biantailajiao.com"; // 提供商名称
const API_URL_V4: &str = "https://ip.biantailajiao.com/ip"; // IPv4 API URL
const API_URL_V6: &str = "https://ip6.biantailajiao.com/ip"; // IPv6 API URL

// 为 BiantailajiaoCom 实现 IpCheck trait
#[async_trait]
impl IpCheck for BiantailajiaoCom {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            // 此 API 不支持查询指定 IP
            return vec![not_support_error(PROVIDER_NAME)];
        }

        let mut results = Vec::new();

        // 异步查询 IPv4 地址
        let handle_v4 = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            // 创建仅使用 IPv4 的 reqwest 客户端
            let client_v4 = match create_reqwest_client(Some(false)).await {
                Ok(c) => c,
                Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
            };

            // 发送 GET 请求
            let response_result = client_v4
                .get(API_URL_V4)
                .headers(ip233_style_headers().await)
                .send()
                .await;
            // 解析响应
            let mut result = match response_result {
                Ok(r) => parse_ip233_style_resp(r, PROVIDER_NAME).await,
                Err(e) => request_error_ip_result(PROVIDER_NAME, &format!("IPv4 request: {e}")),
            };
            // 计算耗时
            result.used_time = Some(time_start.elapsed());
            result
        });

        // 异步查询 IPv6 地址
        let handle_v6 = tokio::spawn(async move {
            let time_start = tokio::time::Instant::now();
            // 创建仅使用 IPv6 的 reqwest 客户端
            let client_v6 = match create_reqwest_client(Some(true)).await {
                Ok(c) => c,
                Err(_) => return create_reqwest_client_error(PROVIDER_NAME),
            };

            // 发送 GET 请求
            let response_result = client_v6
                .get(API_URL_V6)
                .headers(ip233_style_headers().await)
                .send()
                .await;
            // 解析响应
            let mut result = match response_result {
                Ok(r) => parse_ip233_style_resp(r, PROVIDER_NAME).await,
                Err(e) => request_error_ip_result(PROVIDER_NAME, &format!("IPv6 request: {e}")),
            };
            // 计算耗时
            result.used_time = Some(time_start.elapsed());
            result
        });

        // 等待并收集结果
        if let Ok(r) = handle_v4.await {
            results.push(r);
        }
        if let Ok(r) = handle_v6.await {
            // 避免重复添加相同的 IP
            if !results.iter().any(|res| res.success && res.ip == r.ip) {
                results.push(r);
            }
        }
        results
    }
}
