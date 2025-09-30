// 引用 clap 库，用于解析命令行参数
use clap::Parser;

// 使用 clap 的 Parser 派生宏，定义命令行参数的结构体
#[allow(clippy::struct_excessive_bools)]
#[derive(Parser, Debug)]
// 定义命令的名称、版本和关于信息
#[command(name = "IP-Hacker", version, about)]
pub struct Config {
    /// 显示所有信息
    #[arg(short, long, default_value_t = false)]
    pub all: bool,

    /// 显示提供商名称
    #[arg(long, default_value_t = false)]
    pub provider: bool,

    /// 显示 IP 地址
    #[arg(long, default_value_t = false)]
    pub ip: bool,

    /// 显示 ASN 信息
    #[arg(long, default_value_t = false)]
    pub asn: bool,

    /// 显示 ISP 名称
    #[arg(long, default_value_t = false)]
    pub isp: bool,

    /// 显示国家
    #[arg(long, default_value_t = false)]
    pub country: bool,

    /// 显示地区
    #[arg(long, default_value_t = false)]
    pub region: bool,

    /// 显示城市
    #[arg(long, default_value_t = false)]
    pub city: bool,

    /// 显示坐标
    #[arg(long, default_value_t = false)]
    pub coordinates: bool,

    /// 显示时区
    #[arg(long, default_value_t = false)]
    pub time_zone: bool,

    /// 显示风险评分
    #[arg(long, default_value_t = false)]
    pub risk: bool,

    /// 显示风险标签
    #[arg(long, default_value_t = false)]
    pub tags: bool,

    /// 显示处理时间
    #[arg(long, default_value_t = false)]
    pub time: bool,

    /// 设置 IP 地址
    #[arg(short, long)]
    pub set_ip: Option<String>,

    /// 不清屏
    #[arg(long, default_value_t = false)]
    pub cls: bool,

    /// 不显示 Logo
    #[arg(long, default_value_t = false)]
    pub no_logo: bool,

    /// 不上传结果
    #[arg(long, default_value_t = false)]
    pub no_upload: bool,

    /// 显示日志输出
    #[arg(long, default_value_t = true)]
    pub logger: bool,

    /// Json 格式输出
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// 为 IP-Hacker-GUI 提供特殊支持
    #[arg(long, default_value_t = false)]
    pub special_for_gui: bool,
}

// 定义一个函数，用于处理默认配置
pub fn default_config(config: Config) -> Config {
    // 如果指定了 json 输出
    if config.json {
        // 返回一个包含所有信息、json 输出、无 logo、不清屏、不上传、无日志的配置
        Config {
            all: true,
            json: true,
            no_logo: true,
            cls: false,
            no_upload: true,
            logger: false,
            ..config
        }
    // 如果指定了任何一个显示项
    } else if config.provider
        || config.ip
        || config.asn
        || config.isp
        || config.country
        || config.region
        || config.city
        || config.coordinates
        || config.time_zone
        || config.risk
        || config.tags
        || config.time
    {
        // 直接返回原始配置
        config
    // 如果指定了显示所有信息
    } else if config.all {
        // 返回一个包含所有详细信息的配置
        Config {
            provider: true,
            ip: true,
            asn: true,
            isp: true,
            country: true,
            region: true,
            city: true,
            coordinates: true,
            time_zone: true,
            risk: true,
            tags: true,
            time: true,
            ..config
        }
    // 如果是为 GUI 提供特殊支持
    } else if config.special_for_gui {
        // 返回一个为 GUI 优化的配置
        Config {
            all: true,
            json: false,
            no_logo: true,
            cls: false,
            no_upload: true,
            logger: false,
            ..config
        }
    // 否则，返回默认的配置
    } else {
        Config {
            all: false,
            provider: true,
            ip: true,
            asn: true,
            isp: true,
            country: true,
            region: true,
            city: true,
            coordinates: false,
            time_zone: false,
            risk: false,
            tags: false,
            ..config
        }
    }
}
