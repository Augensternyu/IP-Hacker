use reqwest::Client;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;

pub mod baidu;
pub mod cloudflare;
pub mod dbip_com;
pub mod free_ip_api_com;
pub mod httpbin_org;
pub mod ip_api_com;
pub mod ip_checking;
pub mod ip_checking_maxmind;
pub mod ip_lark_com_digital_element;
pub mod ip_lark_com_ipdata;
pub mod ip_lark_com_ipstack;
pub mod ip_lark_com_maxmind;
pub mod ip_lark_com_moe;
pub mod ip_sb;
pub mod ipapi_co;
pub mod ipinfo_io;
pub mod ipip_net;
pub mod ipquery_io;
pub mod ipwhois_app;
pub mod itdog_cn;
pub mod myip_la;
pub mod ip_lark_com_ipapi;
pub mod ip_lark_com_moon;

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
