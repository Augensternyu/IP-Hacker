// src/ip_check/script/biantailajiao_com.rs

use crate::ip_check::ip_result::{
    create_reqwest_client_error, not_support_error, request_error_ip_result, IpResult,
};
use crate::ip_check::script::create_reqwest_client;
use crate::ip_check::script::ip233_cn::{ip233_style_headers, parse_ip233_style_resp};
use crate::ip_check::IpCheck;
use async_trait::async_trait;
use std::net::IpAddr;

pub struct BiantailajiaoCom;

const PROVIDER_NAME: &str = "Biantailajiao.com";
const API_URL_V4: &str = "https://ip.biantailajiao.com/ip";
const API_URL_V6: &str = "https://ip6.biantailajiao.com/ip";

#[async_trait]
impl IpCheck for BiantailajiaoCom {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            return vec![not_support_error(PROVIDER_NAME)];
        }

        let mut results = Vec::new();

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
            result.used_time = Some(time_start.elapsed());
            result
        });

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
            if !results.iter().any(|res| res.success && res.ip == r.ip) {
                results.push(r);
            }
        }
        results
    }
}
