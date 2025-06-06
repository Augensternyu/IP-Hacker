use crate::ip_check::IpCheck;
use crate::ip_check::ip_result::IpCheckError::No;
use crate::ip_check::ip_result::{
    IpResult, Region, create_reqwest_client_error, json_parse_error_ip_result,
    request_error_ip_result,
};
use crate::ip_check::script::create_reqwest_client;
use async_trait::async_trait;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub struct DbIpCom;

#[async_trait]
impl IpCheck for DbIpCom {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            let handle = tokio::spawn(async move {
                let Ok(client) = create_reqwest_client(Some("curl/8.11.1"), None).await else {
                    return create_reqwest_client_error("Db-Ip.com");
                };

                let Ok(result) = client
                    .get(format!("https://api.db-ip.com/v2/free/{ip}"))
                    .send()
                    .await
                else {
                    return request_error_ip_result("Db-Ip.com", "Unable to connect to ipip.net");
                };

                get_db_ip_com_info(result).await
            });

            vec![handle.await.unwrap_or(json_parse_error_ip_result(
                "Db-Ip.com",
                "Unable to parse json",
            ))]
        } else {
            let handle_v4 = tokio::spawn(async move {
                let Ok(client_v4) = create_reqwest_client(Some("curl/8.11.1"), Some(false)).await
                else {
                    return create_reqwest_client_error("Db-Ip.com");
                };

                let Ok(result) = client_v4
                    .get("https://api.db-ip.com/v2/free/self")
                    .send()
                    .await
                else {
                    return request_error_ip_result("Db-Ip.com", "Unable to connect to ipip.net");
                };

                get_db_ip_com_info(result).await
            });

            vec![handle_v4.await.unwrap_or(json_parse_error_ip_result(
                "Db-Ip.com",
                "Unable to parse json",
            ))]
        }
    }
}

async fn get_db_ip_com_info(resp: Response) -> IpResult {
    #[derive(Deserialize, Serialize)]
    struct DbIpComResp {
        #[serde(rename = "ipAddress")]
        ip: IpAddr,

        #[serde(rename = "countryName")]
        country_name: Option<String>,

        #[serde(rename = "stateProv")]
        state_prov: Option<String>,

        city: Option<String>,
    }

    let Ok(json) = resp.json::<DbIpComResp>().await else {
        return json_parse_error_ip_result(
            "Db-Ip.com",
            "Unable to parse the returned result into Json",
        );
    };

    IpResult {
        success: true,
        error: No,
        provider: "Db-Ip.com".to_string(),
        ip: Some(json.ip),
        autonomous_system: None,
        region: Some(Region {
            country: json.country_name,
            region: json.state_prov,
            city: json.city,
            coordinates: None,
            time_zone: None,
        }),
        risk: None,
    }
}
