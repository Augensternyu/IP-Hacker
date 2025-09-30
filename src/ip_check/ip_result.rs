// 引入当前模块中的错误类型
use crate::ip_check::ip_result::IpCheckError::{CreateReqwestClient, JsonParse, ParseIP, Request};
// 引入 serde 库，用于序列化和反序列化
use serde::{Deserialize, Serialize};
// 引入标准库中的格式化和 IP 地址相关模块
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::time::Duration;

// 定义 IP 检查错误的枚举类型
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub enum IpCheckError {
    #[default]
    No, // 无错误
    JsonParse(String), // JSON 解析错误
    Request(String), // 请求错误
    ParseIP(String), // IP 地址解析错误
    CreateReqwestClient, // 创建 Reqwest 客户端错误
    NotSupport, // 不支持指定 IP
}

// 创建一个表示 JSON 解析错误的 IpResult
pub fn json_parse_error_ip_result(provider: &str, message: &str) -> IpResult {
    IpResult {
        success: false,
        error: JsonParse(message.to_string()),
        provider: provider.to_string(),
        ip: None,
        autonomous_system: None,
        region: None,
        risk: None,
        used_time: None,
    }
}

// 创建一个表示请求错误的 IpResult
pub fn request_error_ip_result(provider: &str, message: &str) -> IpResult {
    IpResult {
        success: false,
        error: Request(message.to_string()),
        provider: provider.to_string(),
        ip: None,
        autonomous_system: None,
        region: None,
        risk: None,
        used_time: None,
    }
}

// 创建一个表示 IP 解析错误的 IpResult
pub fn parse_ip_error_ip_result(provider: &str, message: &str) -> IpResult {
    IpResult {
        success: false,
        error: ParseIP(message.to_string()),
        provider: provider.to_string(),
        ip: None,
        autonomous_system: None,
        region: None,
        risk: None,
        used_time: None,
    }
}

// 创建一个表示创建 Reqwest 客户端错误的 IpResult
pub fn create_reqwest_client_error(provider: &str) -> IpResult {
    IpResult {
        success: false,
        error: CreateReqwestClient,
        provider: provider.to_string(),
        ip: None,
        autonomous_system: None,
        region: None,
        risk: None,
        used_time: None,
    }
}

// 创建一个表示不支持错误的 IpResult
pub fn not_support_error(provider: &str) -> IpResult {
    IpResult {
        success: false,
        error: IpCheckError::NotSupport,
        provider: provider.to_string(),
        ip: None,
        autonomous_system: None,
        region: None,
        risk: None,
        used_time: None,
    }
}

// 定义 IP 检查结果的结构体
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct IpResult {
    pub success: bool, // 是否成功
    pub error: IpCheckError, // 错误信息
    pub provider: String, // 提供商名称
    pub ip: Option<IpAddr>, // IP 地址
    pub autonomous_system: Option<AS>, // 自治系统信息
    pub region: Option<Region>, // 地区信息
    pub risk: Option<Risk>, // 风险信息
    pub used_time: Option<Duration>, // 使用时间
}

// 定义自治系统 (AS) 的结构体
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AS {
    pub number: u32, // AS 号码
    pub name: String, // AS 名称
}

// 定义地区信息的结构体
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Region {
    pub country: Option<String>, // 国家
    pub region: Option<String>, // 地区/省份
    pub city: Option<String>, // 城市
    pub coordinates: Option<Coordinates>, // 坐标
    pub time_zone: Option<String>, // 时区
}

// 定义坐标的结构体
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Coordinates {
    pub latitude: String, // 纬度
    pub longitude: String, // 经度
}

// 定义风险信息的结构体
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Risk {
    pub risk: Option<u16>, // 风险评分
    pub tags: Option<Vec<RiskTag>>, // 风险标签
}

// 定义风险标签的枚举类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RiskTag {
    Tor, // Tor 网络
    Proxy, // 代理
    Hosting, // 主机托管
    Relay, // 中继
    Mobile, // 移动网络
    Other(String), // 其他
}

// 定义一个 trait，用于对 IpResult 的 Vec 进行扩展
pub trait IpResultVecExt {
    fn sort_by_name(&mut self);
}

// 为 Vec<IpResult> 实现 IpResultVecExt trait
impl IpResultVecExt for Vec<IpResult> {
    // 按名称对 IpResult 向量进行排序
    fn sort_by_name(&mut self) {
        // 使用不稳定的排序算法，性能更好
        self.sort_unstable_by(|a, b| {
            // 获取 IP 地址字符串的长度
            let len_a = a.ip.as_ref().map_or(0, |ip| ip.to_string().len());
            let len_b = b.ip.as_ref().map_or(0, |ip| ip.to_string().len());

            // 首先按 IP 长度排序，然后按提供商名称排序，最后按使用时间排序
            len_a
                .cmp(&len_b)
                .then_with(|| a.provider.cmp(&b.provider))
                .then_with(|| a.used_time.cmp(&b.used_time))
        });
    }
}

// 为 IpResult 实现 Display trait，用于自定义显示格式
impl Display for IpResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.success {
            if let Some(ip) = &self.ip {
                write!(f, "{} Done: {}", self.provider, ip)
            } else {
                write!(f, "{} Done but have no IP", self.provider)
            }
        } else {
            write!(f, "{} Error: {}", self.provider, self.error)
        }
    }
}
