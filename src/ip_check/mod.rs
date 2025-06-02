mod ip_result;
mod script;
pub mod table;

use crate::config::Config;
use crate::ip_check::ip_result::{IpCheckError, IpResult};
use crate::ip_check::script::{
    cloudflare, dbip_com, ip_api_com, ip_checking, ip_sb, ipapi_co, ipinfo_io, ipip_net,
    ipquery_io, maxmind, myip_la,
};
use async_trait::async_trait;
use log::{info, warn};
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use tokio::sync::mpsc;

#[async_trait]
#[allow(dead_code)]
pub trait IpCheck {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult>; // 本机 IP 或者指定 IP (不一定每一个 Provider 都支持)
}

pub async fn check_all(_config: &Config, ip: Option<IpAddr>) -> Vec<IpResult> {
    let provider_list: Vec<Box<dyn IpCheck + Send + Sync>> = vec![
        Box::new(ip_checking::IpChecking),
        Box::new(maxmind::Maxmind),
        Box::new(ipinfo_io::IpInfoIo),
        Box::new(cloudflare::Cloudflare),
        Box::new(ip_sb::IpSb),
        Box::new(ipip_net::IpIpNet),
        Box::new(ipquery_io::IpQueryIo),
        Box::new(myip_la::MyIPLa),
        Box::new(ipapi_co::IPApiCo),
        Box::new(ip_api_com::IpApiCom),
        Box::new(dbip_com::DbIpCom),
    ];

    let (tx, mut rx) = mpsc::channel(100);

    let _time = tokio::time::Instant::now();

    for provider in provider_list {
        let tx = tx.clone();
        tokio::spawn(async move {
            let result = provider.check(ip).await;
            tx.send(result).await.unwrap();
        });
    }

    drop(tx);

    let mut results = vec![];
    while let Some(result) = rx.recv().await {
        results.extend(result.clone());

        for result_single in result {
            if result_single.success {
                info!("{} check succeeded", result_single.provider);
            } else {
                warn!(
                    "{} check failed, message: {}",
                    result_single.provider, result_single.error
                );
            }
        }
    }
    results
}

impl Display for IpCheckError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            IpCheckError::No => {
                write!(f, "Why would you include a NoError in a failed request?")
            }
            IpCheckError::JsonParse(message) => write!(f, "Json: {message}"),
            IpCheckError::Request(message) => write!(f, "Request: {message}"),
            IpCheckError::ParseIP(message) => write!(f, "Request: {message}"),
            IpCheckError::CreateReqwestClient => write!(f, "Create Reqwest Client Error"),
            IpCheckError::NotSupport => {
                write!(
                    f,
                    "This provider does not currently support the specified IP"
                )
            }
        }
    }
}
