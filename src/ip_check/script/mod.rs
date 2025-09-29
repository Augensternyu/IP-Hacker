// 引入 reqwest 库，用于发送 HTTP 请求
use reqwest::Client;
// 引入标准库中的 IP 地址和时间相关模块
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
// 引入 tokio 的 OnceCell，用于异步环境下的单次初始化
use tokio::sync::OnceCell;

// 声明所有 IP 查询脚本模块
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
pub mod mullvad_net;
pub mod airvpn_org;

// 使用 OnceCell 定义静态的 reqwest Client 实例，用于复用
// 针对 IPv4 的客户端
static CLIENT_IPV4: OnceCell<Client> = OnceCell::const_new();
// 针对 IPv6 的客户端
static CLIENT_IPV6: OnceCell<Client> = OnceCell::const_new();
// 默认的客户端
static CLIENT_DEFAULT: OnceCell<Client> = OnceCell::const_new();

// 定义一个异步函数，用于创建或获取 reqwest 客户端
pub async fn create_reqwest_client(ipv6: Option<bool>) -> Result<&'static Client, reqwest::Error> {
    match ipv6 {
        // 如果指定使用 IPv6
        Some(true) => {
            // 尝试获取或初始化 IPv6 客户端
            CLIENT_IPV6
                .get_or_try_init(|| async {
                    Client::builder()
                        .timeout(Duration::from_secs(5)) // 设置超时时间
                        .cookie_store(true) // 启用 cookie
                        .local_address(Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED))) // 绑定到任意 IPv6 地址
                        .user_agent("curl/7.88.1") // 设置 User-Agent
                        .build() // 构建客户端
                })
                .await
        }
        // 如果指定使用 IPv4
        Some(false) => {
            // 尝试获取或初始化 IPv4 客户端
            CLIENT_IPV4
                .get_or_try_init(|| async {
                    Client::builder()
                        .timeout(Duration::from_secs(5))
                        .cookie_store(true)
                        .local_address(Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED))) // 绑定到任意 IPv4 地址
                        .user_agent("curl/7.88.1")
                        .build()
                })
                .await
        }
        // 如果未指定 IP 版本
        None => {
            // 尝试获取或初始化默认客户端
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
