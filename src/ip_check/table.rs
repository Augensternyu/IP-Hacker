// 引入项目内的模块和外部库
use crate::config::Config; // 引入配置模块
use crate::ip_check::ip_result::{IpResult, RiskTag}; // 引入 IP 检查结果和风险标签类型
use prettytable::{color, format, Attr, Cell, Row, Table}; // 引入 prettytable 库，用于创建格式化的表格

// 定义一个异步函数 gen_table，用于根据 IP 检查结果生成表格
pub async fn gen_table(ip_results_vec: &Vec<IpResult>, config: &Config) -> Table {
    // 创建一个新的表格实例
    let mut table = Table::new();
    // 设置表格的格式，这里使用了无边框线的格式
    table.set_format(*format::consts::FORMAT_NO_LINESEP);
    // 设置表格的标题行
    table.set_titles(Row::new(make_table_cells(config)));

    // 遍历 IP 检查结果向量
    for ip_result in ip_results_vec {
        // 为每个结果创建表格行，如果成功则添加到表格中
        if let Some(row) = make_table_row(ip_result.clone(), config) {
            table.add_row(row);
        }
    }
    // 返回生成的表格
    table
}

// 定义一个函数 make_table_cells，用于根据配置创建表格的标题单元格
pub(crate) fn make_table_cells(config: &Config) -> Vec<Cell> {
    let mut cells = Vec::new();
    // 根据配置决定是否添加 "Provider" 列
    if config.provider {
        cells.push(
            Cell::new("Provider")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        );
    }
    // 根据配置决定是否添加 "IP" 列
    if config.ip {
        cells.push(
            Cell::new("IP")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        );
    }
    // 根据配置决定是否添加 "ASN" 列
    if config.asn {
        cells.push(
            Cell::new("ASN")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        );
    }
    // 根据配置决定是否添加 "ISP" 列
    if config.isp {
        cells.push(
            Cell::new("ISP")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        );
    }
    // 根据配置决定是否添加 "Country" 列
    if config.country {
        cells.push(
            Cell::new("Country")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        );
    }
    // 根据配置决定是否添加 "Region" 列
    if config.region {
        cells.push(
            Cell::new("Region")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        );
    }
    // 根据配置决定是否添加 "City" 列
    if config.city {
        cells.push(
            Cell::new("City")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        );
    }
    // 根据配置决定是否添加坐标列
    if config.coordinates {
        cells.push(
            Cell::new("Lat")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        );
        cells.push(
            Cell::new("Lon")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        );
    }
    // 根据配置决定是否添加 "Time Zone" 列
    if config.time_zone {
        cells.push(
            Cell::new("Time Zone")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        );
    }
    // 根据配置决定是否添加 "Risk" 列
    if config.risk {
        cells.push(
            Cell::new("Risk")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        );
    }
    // 根据配置决定是否添加 "Tags" 列
    if config.tags {
        cells.push(
            Cell::new("Tags")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        );
    }
    // 根据配置决定是否添加 "Processing Time" 列
    if config.time {
        cells.push(
            Cell::new("Processing Time")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        );
    }
    cells
}

// 定义一个函数 make_table_row，用于根据单个 IP 检查结果创建表格行
pub(crate) fn make_table_row(ip_result: IpResult, config: &Config) -> Option<Row> {
    let mut rows_vec = Vec::new();

    // 如果检查不成功，则不创建行
    if !ip_result.success {
        return None;
    }

    // 根据配置添加 "Provider" 单元格
    if config.provider {
        rows_vec.push(
            Cell::new(ip_result.provider.as_str()).with_style(Attr::ForegroundColor(color::YELLOW)),
        );
    }

    // 根据配置添加 "IP" 单元格，并根据 IP 版本设置不同颜色
    if config.ip {
        if let Some(ip) = ip_result.ip {
            if ip.is_ipv4() {
                rows_vec.push(
                    Cell::new(&ip.to_string())
                        .with_style(Attr::ForegroundColor(color::BRIGHT_BLUE)),
                );
            } else {
                rows_vec.push(
                    Cell::new(&ip.to_string()).with_style(Attr::ForegroundColor(color::BLUE)),
                );
            }
        } else {
            rows_vec.push(Cell::new(""));
        }
    }

    // 解析 ASN 和 ISP 信息
    let (asn, isp) = if let Some(a_s) = ip_result.autonomous_system {
        if a_s.number == 0 {
            (String::new(), a_s.name)
        } else {
            (a_s.number.to_string(), a_s.name)
        }
    } else {
        (String::new(), String::new())
    };

    // 根据配置添加 "ASN" 单元格
    if config.asn {
        rows_vec
            .push(Cell::new(asn.as_str()).with_style(Attr::ForegroundColor(color::BRIGHT_CYAN)));
    }

    // 根据配置添加 "ISP" 单元格
    if config.isp {
        rows_vec.push(Cell::new(isp.as_str()).with_style(Attr::ForegroundColor(color::CYAN)));
    }

    // 解析地区、坐标和时区信息
    let (country, region, city, (lat, lon), time_zone) = if let Some(region) = ip_result.region {
        (
            region.country.unwrap_or(String::new()),
            region.region.unwrap_or(String::new()),
            region.city.unwrap_or(String::new()),
            if let Some(coordinates) = region.coordinates {
                (
                    coordinates.latitude.to_string(),
                    coordinates.longitude.to_string(),
                )
            } else {
                (String::new(), String::new())
            },
            region.time_zone.unwrap_or(String::new()),
        )
    } else {
        (
            String::new(),
            String::new(),
            String::new(),
            (String::new(), String::new()),
            String::new(),
        )
    };

    // 根据配置添加 "Country" 单元格
    if config.country {
        rows_vec.push(Cell::new(country.as_str()).with_style(Attr::ForegroundColor(color::GREEN)));
    }

    // 根据配置添加 "Region" 单元格
    if config.region {
        rows_vec.push(Cell::new(region.as_str()).with_style(Attr::ForegroundColor(color::GREEN)));
    }

    // 根据配置添加 "City" 单元格
    if config.city {
        rows_vec.push(Cell::new(city.as_str()).with_style(Attr::ForegroundColor(color::GREEN)));
    }

    // 根据配置添加坐标单元格
    if config.coordinates {
        rows_vec
            .push(Cell::new(lat.as_str()).with_style(Attr::ForegroundColor(color::BRIGHT_GREEN)));
        rows_vec
            .push(Cell::new(lon.as_str()).with_style(Attr::ForegroundColor(color::BRIGHT_GREEN)));
    }

    // 根据配置添加 "Time Zone" 单元格
    if config.time_zone {
        rows_vec.push(
            Cell::new(time_zone.as_str()).with_style(Attr::ForegroundColor(color::BRIGHT_MAGENTA)),
        );
    }

    // 解析风险和标签信息
    let (risk, tags) = if let Some(risk) = ip_result.risk {
        (
            if let Some(risk) = risk.risk {
                risk.to_string()
            } else {
                String::new()
            },
            risk.tags.unwrap_or_default(),
        )
    } else {
        (String::new(), vec![])
    };

    // 将风险标签转换为字符串
    let mut risk_tags = Vec::new();
    for tag in tags {
        risk_tags.push(match tag {
            RiskTag::Tor => "TOR".to_string(),
            RiskTag::Proxy => "PROXY".to_string(),
            RiskTag::Hosting => "HOSTING".to_string(),
            RiskTag::Relay => "RELAY".to_string(),
            RiskTag::Mobile => "MOBILE".to_string(),
            RiskTag::Other(str) => str,
        });
    }
    let risk_tags_str = risk_tags.join(", ");

    // 根据配置添加 "Risk" 单元格
    if config.risk {
        rows_vec.push(Cell::new(risk.as_str()).with_style(Attr::ForegroundColor(color::RED)));
    }

    // 根据配置添加 "Tags" 单元格
    if config.tags {
        rows_vec.push(
            Cell::new(risk_tags_str.as_str())
                .with_style(Attr::ForegroundColor(color::BRIGHT_YELLOW)),
        );
    }

    // 根据配置添加 "Processing Time" 单元格
    if config.time {
        if let Some(time) = ip_result.used_time {
            rows_vec.push(
                Cell::new(format!("{}ms", time.as_millis()).as_str())
                    .with_style(Attr::ForegroundColor(color::BRIGHT_WHITE)),
            );
        } else {
            rows_vec.push(Cell::new(""));
        }
    }

    // 返回创建的行
    Some(Row::new(rows_vec))
}
