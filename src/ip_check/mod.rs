// 声明 ip_result 模块，并设置为 crate 内可见
pub(crate) mod ip_result;
// 声明 script 模块
mod script;
// 声明 table 模块，并设置为公共可见
pub mod table;

// 引入项目内的模块和外部库
use crate::config::Config; // 引入配置模块
use crate::ip_check::ip_result::{IpCheckError, IpResult}; // 引入 IP 检查结果和错误类型
// 引入所有 IP 查询脚本
use crate::ip_check::script::{abstractapi_com, airvpn_org, apiip_net, apilayer_com, apip_cc, baidu, biantailajiao_com, bilibili, cloudflare, cz88_net, dashi_163_com, dbip_com, free_ip_api_com, geoapify_com, geoplugin_net, hsselite_com, httpbin_org, ip125_com, ip233_cn, ip234_in, ip2location_io, ip_api_com, ip_checking, ip_checking_maxmind, ip_lark_com_digital_element, ip_lark_com_ipapi, ip_lark_com_ipdata, ip_lark_com_ipstack, ip_lark_com_maxmind, ip_lark_com_moe, ip_lark_com_moon, ip_sb, ipapi_co, ipapi_is, ipbase_com, ipdata_co, ipgeolocation_io, ipinfo_io, ipip_net, ipleak_net, iplocation_net, ipquery_io, ipw_cn, ipwho_is, ipwhois_app, itdog_cn, keycdn_com, maptiler_com, meituan_com, mullvad_net, myip_la, myip_wtf, nameless13_xyz, qq_com, realip_cc, reallyfreegeoip_org, taobao_com, vvhan_com};
use async_trait::async_trait; // 引入 async_trait 宏，用于在 trait 中定义异步函数
use std::fmt::{Display, Formatter}; // 引入格式化相关的 trait
use std::net::IpAddr; // 引入 IP 地址类型
use tokio::sync::mpsc; // 引入 tokio 的多生产者单消费者通道

// 使用 async_trait 宏定义一个异步的 IpCheck trait
#[async_trait]
#[allow(dead_code)] // 允许存在未使用的代码
pub trait IpCheck {
    // 定义一个异步的 check 方法，用于检查 IP 地址
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult>; // 参数可以是本机 IP (None) 或者指定的 IP
}

// 定义一个异步函数 check_all，用于执行所有 IP 查询
pub fn check_all(_config: &Config, ip: Option<IpAddr>) -> mpsc::Receiver<IpResult> {
    // 创建一个包含所有 IP 查询提供者的列表
    let provider_list: Vec<Box<dyn IpCheck + Send + Sync>> = vec![
        Box::new(ip_checking::IpChecking),
        Box::new(ip_checking_maxmind::Maxmind),
        Box::new(ipinfo_io::IpInfoIo),
        Box::new(cloudflare::Cloudflare),
        Box::new(ip_sb::IpSb),
        Box::new(ipip_net::IpIpNet),
        Box::new(ipquery_io::IpQueryIo),
        Box::new(myip_la::MyIPLa),
        Box::new(ipapi_co::IPApiCo),
        Box::new(ip_api_com::IpApiCom),
        Box::new(dbip_com::DbIpCom),
        Box::new(free_ip_api_com::FreeIpApiCom),
        Box::new(ipwhois_app::IpWhoisApp),
        Box::new(httpbin_org::HttpBinOrg),
        Box::new(itdog_cn::ItDogCn),
        Box::new(baidu::Baidu),
        Box::new(ip_lark_com_maxmind::IpLarkComMaxmind),
        Box::new(ip_lark_com_digital_element::IpLarkComDigitalElement),
        Box::new(ip_lark_com_ipstack::IpLarkComIpStack),
        Box::new(ip_lark_com_moe::IpLarkComMoe),
        Box::new(ip_lark_com_ipdata::IpLarkComIpData),
        Box::new(ip_lark_com_ipapi::IpLarkComIpApi),
        Box::new(ip_lark_com_moon::IpLarkComMoon),
        Box::new(bilibili::Bilibili),
        Box::new(myip_wtf::MyIpWtf),
        Box::new(ip234_in::Ip234In),
        Box::new(ip2location_io::Ip2locationIo),
        Box::new(ipdata_co::IpdataCo),
        Box::new(ipwho_is::IpwhoIs),
        Box::new(ipgeolocation_io::IpgeolocationIo),
        Box::new(vvhan_com::VvhanCom),
        Box::new(cz88_net::Cz88Net),
        Box::new(ipw_cn::IpwCn),
        Box::new(ip125_com::Ip125Com),
        Box::new(reallyfreegeoip_org::ReallyfreegeoipOrg),
        Box::new(ipleak_net::IpleakNet),
        Box::new(realip_cc::RealipCc),
        Box::new(ipbase_com::IpbaseCom),
        Box::new(dashi_163_com::Dashi163Com),
        Box::new(hsselite_com::HsseliteCom),
        Box::new(qq_com::QqCom),
        Box::new(ip233_cn::Ip233Cn),
        Box::new(nameless13_xyz::Nameless13Xyz),
        Box::new(biantailajiao_com::BiantailajiaoCom),
        Box::new(taobao_com::TaobaoCom),
        Box::new(meituan_com::MeituanCom),
        Box::new(apiip_net::ApiipNet),
        Box::new(geoplugin_net::GeopluginNet),
        Box::new(ipapi_is::IpapiIs),
        Box::new(apip_cc::ApipCc),
        Box::new(iplocation_net::IplocationNet),
        Box::new(apilayer_com::ApilayerCom),
        Box::new(geoapify_com::GeoapifyCom),
        Box::new(keycdn_com::KeycdnCom),
        Box::new(maptiler_com::MaptilerCom),
        Box::new(abstractapi_com::AbstractapiCom),
        Box::new(mullvad_net::MullvadNet),
        Box::new(airvpn_org::AirvpnOrg),
    ];

    // 创建一个 tokio mpsc 通道，用于在不同任务间传递结果
    let (tx, rx) = mpsc::channel(32);

    // 创建一个新的异步任务来处理所有的 IP 查询
    tokio::spawn(async move {
        // 遍历提供者列表
        for provider in provider_list {
            // 克隆通道的发送端和 IP 地址
            let tx = tx.clone();
            let ip_clone = ip;
            // 为每个提供者创建一个新的异步任务
            tokio::spawn(async move {
                // 调用提供者的 check 方法
                let results = provider.check(ip_clone).await;
                // 遍历查询结果
                for result in results {
                    // 发送结果到通道，如果发送失败则退出循环
                    if tx.send(result).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    // 返回通道的接收端
    rx
}

// 为 IpCheckError 实现 Display trait，用于自定义错误信息的显示格式
impl Display for IpCheckError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            // 理论上不应该出现的错误
            IpCheckError::No => {
                write!(f, "Why would you include a NoError in a failed request?")
            }
            // JSON 解析错误
            IpCheckError::JsonParse(message) => write!(f, "Json: {message}"),
            // 请求错误
            IpCheckError::Request(message) | IpCheckError::ParseIP(message) => {
                write!(f, "Request: {message}")
            }
            // 创建 Reqwest 客户端错误
            IpCheckError::CreateReqwestClient => write!(f, "Create Reqwest Client Error"),
            // 不支持指定 IP 的错误
            IpCheckError::NotSupport => {
                write!(
                    f,
                    "This provider does not currently support the specified IP"
                )
            }
        }
    }
}
