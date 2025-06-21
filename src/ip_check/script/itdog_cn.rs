use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    IpResult, create_reqwest_client_error, not_support_error, request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct ItDogCn;

#[async_trait]
impl IpCheck for ItDogCn {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if ip.is_some() {
            vec![not_support_error("Itdog.cn")]
        } else {
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();
                let Ok(client_v4) = create_reqwest_client(Some(true)).await else {
                    return create_reqwest_client_error("Itdog.cn");
                };

                let Ok(result) = client_v4.get("https://ipv6.itdog.cn/").send().await else {
                    return request_error_ip_result("Itdog.cn", "Unable to connect");
                };

                #[derive(Deserialize, Serialize)]
                struct HttpBinOrgResp {
                    ip: IpAddr,
                }

                let ip = result.json::<HttpBinOrgResp>().await.map(|resp| resp.ip);

                if let Ok(ip) = ip {
                    IpResult {
                        success: true,
                        error: No,
                        provider: "Itdog.cn".to_string(),
                        ip: Some(ip),
                        autonomous_system: None,
                        region: None,
                        risk: None,
                        used_time: Some(time_start.elapsed()),
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
