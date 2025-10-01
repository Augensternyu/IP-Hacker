// src/ip_check/script/dbip_com.rs

// 引入项目内的模块和外部库
use crate::ip_check::ip_result::IpCheckError::No; // 引入无错误枚举
use crate::ip_check::ip_result::{
    create_reqwest_client_error, json_parse_error_ip_result, request_error_ip_result, IpResult,
    Region,
}; // 引入错误处理函数和结果结构体
use crate::ip_check::script::create_reqwest_client; // 引入 reqwest 客户端创建函数
use crate::ip_check::IpCheck; // 引入 IpCheck trait
use async_trait::async_trait; // 引入 async_trait 宏
use reqwest::Response; // 引入 reqwest 的 Response
use serde::{Deserialize, Serialize}; // 引入 serde 的 Deserialize 和 Serialize
use std::net::IpAddr; // 引入 IpAddr

// 定义 DbIpCom 结构体
pub struct DbIpCom;

// 为 DbIpCom 实现 IpCheck trait
#[async_trait]
impl IpCheck for DbIpCom {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult> {
        if let Some(ip) = ip {
            // 如果指定了 IP 地址
            let handle = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();

                // 创建 reqwest 客户端
                let Ok(client) = create_reqwest_client(None).await else {
                    return create_reqwest_client_error("Db-Ip.com");
                };

                // 发送 GET 请求
                let Ok(result) = client
                    .get(format!("https://api.db-ip.com/v2/free/{ip}"))
                    .send()
                    .await
                else {
                    return request_error_ip_result("Db-Ip.com", "Unable to connect");
                };

                // 解析响应并计算耗时
                let mut result_without_time = get_db_ip_com_info(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            vec![handle.await.unwrap_or(json_parse_error_ip_result(
                "Db-Ip.com",
                "Unable to parse json",
            ))]
        } else {
            // 如果未指定 IP 地址，则查询本机 IP
            let handle_v4 = tokio::spawn(async move {
                let time_start = tokio::time::Instant::now();

                // 创建仅使用 IPv4 的 reqwest 客户端
                let Ok(client_v4) = create_reqwest_client(Some(false)).await else {
                    return create_reqwest_client_error("Db-Ip.com");
                };

                // 发送 GET 请求
                let Ok(result) = client_v4
                    .get("https://api.db-ip.com/v2/free/self")
                    .send()
                    .await
                else {
                    return request_error_ip_result("Db-Ip.com", "Unable to connect");
                };

                // 解析响应并计算耗时
                let mut result_without_time = get_db_ip_com_info(result).await;
                let end_time = time_start.elapsed();
                result_without_time.used_time = Some(end_time);
                result_without_time
            });

            vec![handle_v4.await.unwrap_or(json_parse_error_ip_result(
                "Db-Ip.com",
                "Unable to parse json",
            ))]
        }
    }
}

// 解析 Db-Ip.com 的 API 响应
async fn get_db_ip_com_info(resp: Response) -> IpResult {
    // 定义用于反序列化 API 响应的结构体
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

    // 将响应体解析为 JSON
    let Ok(json) = resp.json::<DbIpComResp>().await else {
        return json_parse_error_ip_result(
            "Db-Ip.com",
            "Unable to parse the returned result into Json",
        );
    };

    // 构建 IpResult
    IpResult {
        success: true,
        error: No,
        provider: "Db-Ip.com".to_string(),
        ip: Some(json.ip),
        autonomous_system: None,
        region: Some(Region {
            country: json.country_name,
            province: json.state_prov,
            city: json.city,
            coordinates: None,
            time_zone: None,
        }),
        risk: None,
        used_time: None,
    }
}
