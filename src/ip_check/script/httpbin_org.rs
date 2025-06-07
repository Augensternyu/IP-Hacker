use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    IpResult, create_reqwest_client_error, not_support_error, request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct HttpBinOrg;

#[async_trait]
impl IpCheck for HttpBinOrg {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(_) = ip {
            vec![not_support_error("HttpBin.org")]
        } else {
            let handle_v4 = tokio::spawn(async move {
                let Ok(client_v4) = create_reqwest_client(None, Some(false)).await else {
                    return create_reqwest_client_error("HttpBin.org");
                };

                let Ok(result) = client_v4.get("https://httpbin.org/ip").send().await else {
                    return request_error_ip_result("HttpBin.org", "Unable to connect");
                };

                #[derive(Deserialize, Serialize)]
                struct HttpBinOrgResp {
                    origin: IpAddr,
                }

                let ip = result
                    .json::<HttpBinOrgResp>()
                    .await
                    .map(|resp| resp.origin);

                if let Ok(ip) = ip {
                    return IpResult {
                        success: true,
                        error: No,
                        provider: "HttpBin.org".to_string(),
                        ip: Some(ip),
                        autonomous_system: None,
                        region: None,
                        risk: None,
                    };
                } else {
                    return request_error_ip_result("HttpBin.org", "Unable to connect");
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
