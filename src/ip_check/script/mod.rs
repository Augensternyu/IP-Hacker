use reqwest::Client;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;

pub mod cloudflare;
pub mod ip_checking;
pub mod ip_sb;
pub mod ipinfo_io;
pub mod ipip_net;
pub mod ipquery_io;
pub mod maxmind;
pub mod myip_la;

pub async fn create_reqwest_client(
    ua: Option<&str>,
    ipv6: Option<bool>,
) -> Result<Client, reqwest::Error> {
    let mut builder = Client::builder();
    if ua.is_some() {
        builder = builder.user_agent(ua.unwrap());
    }
    if let Some(ipv6) = ipv6 {
        if ipv6 {
            builder = builder.local_address(Some(IpAddr::V6(Ipv6Addr::from_str("::").unwrap())));
        } else {
            builder =
                builder.local_address(Some(IpAddr::V4(Ipv4Addr::from_str("0.0.0.0").unwrap())));
        }
    }
    builder = builder.cookie_store(true);
    builder = builder.timeout(Duration::from_secs(5));
    builder.build()
}
