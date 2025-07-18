use reqwest::Client;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::sync::OnceCell;

pub mod abstractapi_com;
pub mod apiip_net;
pub mod apilayer_com;
pub mod apip_cc;
pub mod baidu;
pub mod biantailajiao_com;
pub mod bilibili;
pub mod cloudflare;
pub mod cz88_net;
pub mod dashi_163_com;
pub mod dbip_com;
pub mod free_ip_api_com;
pub mod geoapify_com;
pub mod geoplugin_net;
pub mod hsselite_com;
pub mod httpbin_org;
pub mod ip125_com;
pub mod ip233_cn;
pub mod ip234_in;
pub mod ip2location_io;
pub mod ip_api_com;
pub mod ip_checking;
pub mod ip_checking_maxmind;
pub mod ip_lark_com_digital_element;
pub mod ip_lark_com_ipapi;
pub mod ip_lark_com_ipdata;
pub mod ip_lark_com_ipstack;
pub mod ip_lark_com_maxmind;
pub mod ip_lark_com_moe;
pub mod ip_lark_com_moon;
pub mod ip_sb;
pub mod ipapi_co;
pub mod ipapi_is;
pub mod ipbase_com;
pub mod ipdata_co;
pub mod ipgeolocation_io;
pub mod ipinfo_io;
pub mod ipip_net;
pub mod ipleak_net;
pub mod iplocation_net;
pub mod ipquery_io;
pub mod ipw_cn;
pub mod ipwho_is;
pub mod ipwhois_app;
pub mod itdog_cn;
pub mod keycdn_com;
pub mod maptiler_com;
pub mod meituan_com;
pub mod myip_la;
pub mod myip_wtf;
pub mod nameless13_xyz;
pub mod qq_com;
pub mod realip_cc;
pub mod reallyfreegeoip_org;
pub mod taobao_com;
pub mod vvhan_com;

static CLIENT_IPV4: OnceCell<Client> = OnceCell::const_new();
static CLIENT_IPV6: OnceCell<Client> = OnceCell::const_new();
static CLIENT_DEFAULT: OnceCell<Client> = OnceCell::const_new();

pub async fn create_reqwest_client(ipv6: Option<bool>) -> Result<&'static Client, reqwest::Error> {
    match ipv6 {
        Some(true) => {
            // 使用 get_or_try_init
            CLIENT_IPV6
                .get_or_try_init(|| async {
                    Client::builder()
                        .timeout(Duration::from_secs(5))
                        .cookie_store(true)
                        .local_address(Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED))) // 使用常量更佳
                        .user_agent("curl/7.88.1")
                        .build() // 返回 Result<Client, Error>，正好匹配
                })
                .await
        }
        Some(false) => {
            CLIENT_IPV4
                .get_or_try_init(|| async {
                    Client::builder()
                        .timeout(Duration::from_secs(5))
                        .cookie_store(true)
                        .local_address(Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED))) // 使用常量更佳
                        .user_agent("curl/7.88.1")
                        .build()
                })
                .await
        }
        None => {
            CLIENT_DEFAULT
                .get_or_try_init(|| async {
                    Client::builder()
                        .timeout(Duration::from_secs(5))
                        .cookie_store(true)
                        .user_agent("curl/7.88.1")
                        .build()
                })
                .await
        }
    }
}
