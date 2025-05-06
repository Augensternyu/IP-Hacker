use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "IP-Hacker", version, about)]
pub struct Config {
    /// Show All Information
    #[arg(short, long, default_value_t = false)]
    pub all: bool,

    /// Show Provider Name
    #[arg(long, default_value_t = false)]
    pub provider: bool,

    /// Show IP Address
    #[arg(long, default_value_t = false)]
    pub ip: bool,

    /// Show ASN
    #[arg(long, default_value_t = false)]
    pub asn: bool,

    /// Show ISP Name
    #[arg(long, default_value_t = false)]
    pub isp: bool,

    /// Show Country
    #[arg(long, default_value_t = false)]
    pub country: bool,

    /// Show Region
    #[arg(long, default_value_t = false)]
    pub region: bool,

    /// Show City
    #[arg(long, default_value_t = false)]
    pub city: bool,

    /// Show Coordinates
    #[arg(long, default_value_t = false)]
    pub coordinates: bool,

    /// Show Time Zone
    #[arg(long, default_value_t = false)]
    pub time_zone: bool,

    /// Show Risk Score
    #[arg(long, default_value_t = false)]
    pub risk: bool,

    /// Show Risk Tags
    #[arg(long, default_value_t = false)]
    pub tags: bool,

    /// IP Address
    #[arg(short, long)]
    pub set_ip: Option<String>,

    /// No CLS
    #[arg(long, default_value_t = false)]
    pub no_cls: bool,

    /// No Logo
    #[arg(long, default_value_t = false)]
    pub no_logo: bool,

    /// No Upload
    #[arg(long, default_value_t = false)]
    pub no_upload: bool,

    /// No Logger Output
    #[arg(long, default_value_t = false)]
    pub no_logger: bool,

    /// Json Output
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub fn default_config(config: Config) -> Config {
    if config.json {
        Config {
            all: true,
            json: true,
            no_logo: true,
            no_cls: true,
            no_upload: true,
            no_logger: true,
            ..config
        }
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
    {
        config
    } else if config.all {
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
            ..config
        }
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
