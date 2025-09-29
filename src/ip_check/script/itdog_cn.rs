// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, not_support_error, request_error_ip_result, IpResult,
}; // 引入IP检查结果相关的结构体和函数
use crate::ip_check::script::create_reqwest_client; // 引入创建 reqwest 客户端的函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use serde::{Deserialize, Serialize}; // 引入 serde 的 Deserialize 和 Serialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 ItDogCn 结构体
pub struct ItDogCn;

// 为 ItDogCn 实现 IpCheck trait
#[async_trait]
impl IpCheck for ItDogCn {
    // 异步检查 IP 地址
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        // Itdog.cn 不支持查询指定 IP, 只支持查询本机 IP
        if ip.is_some() {
            vec![not_support_error("Itdog.cn")]
        } else {
            // --- 检查本机IP (仅 v6) ---
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                // 强制使用IPv6进行API访问
                let Ok(client_v4) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error("Itdog.cn");
                };

                let Ok(result) = client_v4.get("https://ipv6.itdog.cn/").send().await else {
                    return request_error_ip_result("Itdog.cn", "Unable to connect");
                };

                // 定义用于解析 JSON 响应的内部结构体
                #[derive(Deserialize, Serialize)]
                struct HttpBinOrgResp {
                    ip: IpAddr,
                }

                // 解析 JSON 并获取 IP 地址
                let ip = result.json::<HttpBinOrgResp>().await.map(|resp| resp.ip);

                if let Ok(ip) = ip {
                    // 构建并返回 IpResult
                    IpResult {
                        success: true,
                        error: No,
                        provider: "Itdog.cn".to_string(),
                        ip: Some(ip),
                        autonomous_system: None, // API不提供ASN信息
                        region: None,            // API不提供地理位置信息
                        risk: None,              // API不提供风险信息
                        used_time: Some(time_start.elapsed()), // 记录耗时
                    }
                } else {
                    request_error_ip_result("Itdog.cn", "Unable to connect")
                }
            });

            let mut results = Vec::new();
            if let Ok(result) = handle_v4.await {
                results.push(result);
            }
            results
        }
    }
}
