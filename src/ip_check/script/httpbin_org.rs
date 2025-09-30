// src/ip_check/script/httpbin_org.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, not_support_error, request_error_ip_result, IpResult,
}; // 引入错误处理函数和结果结构体
use crate::ip_check::script::create_reqwest_client; // 引入 reqwest 客户端创建函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use serde::{Deserialize, Serialize}; // 引入 serde 的 Deserialize 和 Serialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 HttpBinOrg 结构体
pub struct HttpBinOrg;

// 定义用于反序列化 API 响应的结构体
#[derive(Deserialize, Serialize)]
struct HttpBinOrgResp {
    origin: IpAddr,
}

// 为 HttpBinOrg 实现 IpCheck trait
#[async_trait]
impl IpCheck for HttpBinOrg {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            // 此 API 不支持查询指定 IP，只返回请求来源的 IP
            vec![not_support_error("HttpBin.org")]
        } else {
            // 异步查询 IPv4 地址
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();

                // 创建仅使用 IPv4 的 reqwest 客户端
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("HttpBin.org");
                };

                // 发送 GET 请求
                let Ok(result) = client_v4.get("https://httpbin.org/ip").send().await else {
                    return request_error_ip_result("HttpBin.org", "Unable to connect");
                };

                // 解析 JSON 响应
                let ip = result
                    .json::<HttpBinOrgResp>()
                    .await
                    .map(|resp| resp.origin);

                // 根据解析结果构建 IpResult
                if let Ok(ip) = ip {
                    IpResult {
                        success: true,
                        error: No,
                        provider: "HttpBin.org".to_string(),
                        ip: Some(ip),
                        autonomous_system: None,
                        region: None,
                        risk: None,
                        used_time: Some(time_start.elapsed()),
                    }
                } else {
                    request_error_ip_result("HttpBin.org", "Unable to parse json")
                }
            });

            // 等待并收集结果
            let mut results = Vec::new();
            if let Ok(result) = handle_v4.await {
                results.push(result);
            }
            results
        }
    }
}
