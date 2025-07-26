pub(crate) mod ip_result;
mod script;
pub mod table;

use crate::config::Config;
use crate::ip_check::ip_result::{IpCheckError, IpResult};
use crate::ip_check::script::{abstractapi_com, apiip_net, apilayer_com, apip_cc, baidu, biantailajiao_com, bilibili, cloudflare, cz88_net, dashi_163_com, dbip_com, free_ip_api_com, geoapify_com, geoplugin_net, hsselite_com, httpbin_org, ip_api_com, ip_checking, ip_checking_maxmind, ip_lark_com_digital_element, ip_lark_com_ipapi, ip_lark_com_ipdata, ip_lark_com_ipstack, ip_lark_com_maxmind, ip_lark_com_moe, ip_lark_com_moon, ip_sb, ip2location_io, ip125_com, ip233_cn, ip234_in, ipapi_co, ipapi_is, ipbase_com, ipdata_co, ipgeolocation_io, ipinfo_io, ipip_net, ipleak_net, iplocation_net, ipquery_io, ipw_cn, ipwho_is, ipwhois_app, itdog_cn, keycdn_com, maptiler_com, meituan_com, myip_la, myip_wtf, nameless13_xyz, qq_com, realip_cc, reallyfreegeoip_org, taobao_com, vvhan_com, mullvad_net, airvpn_org};
use async_trait::async_trait;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use tokio::sync::mpsc;

#[async_trait]
#[allow(dead_code)]
pub trait IpCheck {
    async fn check(&self, ip: Option<IpAddr>) -> Vec<IpResult>; // 本机 IP 或者指定 IP (不一定每一个 Provider 都支持)
}

pub async fn check_all(_config: &Config, ip: Option<IpAddr>) -> mpsc::Receiver<IpResult> {
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

    let (tx, rx) = mpsc::channel(32);

    tokio::spawn(async move {
        for provider in provider_list {
            let tx = tx.clone();
            let ip_clone = ip;
            tokio::spawn(async move {
                let results = provider.check(ip_clone).await;
                for result in results {
                    if tx.send(result).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    rx
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
