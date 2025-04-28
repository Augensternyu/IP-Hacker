mod ip_result;
mod script;
pub mod table;

use crate::config::Config;
use crate::ip_check::ip_result::IpResult;
use crate::ip_check::script::*;
use async_trait::async_trait;
use std::net::IpAddr;
use tokio::sync::mpsc;

#[async_trait]
#[allow(dead_code)]
pub trait IpCheck {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult>; // 本机 IP 或者指定 IP (不一定每一个 Provider 都支持)
}

pub async fn check_all(_config: &Config, ip: Option<IpAddr>) -> Vec<IpResult> {
    let provider_list: Vec<Box<dyn IpCheck + Send + Sync>> =
        vec![Box::new(ip_checking::IpChecking)];

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
        results.extend(result);
    }
    results
}
