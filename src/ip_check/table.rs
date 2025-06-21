use crate::config::Config;
use crate::ip_check::ip_result::{IpResult, RiskTag};
use prettytable::{Attr, Cell, Row, Table, color, format};

pub async fn gen_table(ip_results_vec: &Vec<IpResult>, config: &Config) -> Table {
    let mut table = Table::new();
    // table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    table.set_format(*format::consts::FORMAT_NO_LINESEP);
    table.set_titles(Row::new(make_table_cells(config)));

    for ip_result in ip_results_vec {
        if let Some(row) = make_table_row(ip_result.clone(), config) {
            table.add_row(row);
        }
    }
    table
}

pub(crate) fn make_table_cells(config: &Config) -> Vec<Cell> {
    let mut cells = Vec::new();
    if config.provider {
        cells.push(
            Cell::new("Provider")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        );
    }
    if config.ip {
        cells.push(
            Cell::new("IP")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        );
    }
    if config.asn {
        cells.push(
            Cell::new("ASN")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        );
    }
    if config.isp {
        cells.push(
            Cell::new("ISP")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        );
    }
    if config.country {
        cells.push(
            Cell::new("Country")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        );
    }
    if config.region {
        cells.push(
            Cell::new("Region")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        );
    }
    if config.city {
        cells.push(
            Cell::new("City")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        );
    }
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
    if config.time_zone {
        cells.push(
            Cell::new("Time Zone")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        );
    }
    if config.risk {
        cells.push(
            Cell::new("Risk")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        );
    }
    if config.tags {
        cells.push(
            Cell::new("Tags")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        );
    }
    if config.time {
        cells.push(
            Cell::new("Processing Time")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        );
    }
    cells
}

pub(crate) fn make_table_row(ip_result: IpResult, config: &Config) -> Option<Row> {
    let mut rows_vec = Vec::new();

    if !ip_result.success {
        return None;
    }

    if config.provider {
        rows_vec.push(
            Cell::new(ip_result.provider.as_str()).with_style(Attr::ForegroundColor(color::YELLOW)),
        );
    }

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

    let (asn, isp) = if let Some(a_s) = ip_result.autonomous_system {
        if a_s.number == 0 {
            (String::new(), a_s.name)
        } else {
            (a_s.number.to_string(), a_s.name)
        }
    } else {
        (String::new(), String::new())
    };

    if config.asn {
        rows_vec
            .push(Cell::new(asn.as_str()).with_style(Attr::ForegroundColor(color::BRIGHT_CYAN)));
    }

    if config.isp {
        rows_vec.push(Cell::new(isp.as_str()).with_style(Attr::ForegroundColor(color::CYAN)));
    }

    let (country, region, city, (lat, lon), time_zone) = if let Some(region) = ip_result.region {
        (
            region.country.unwrap_or(String::new()),
            region.region.unwrap_or(String::new()),
            region.city.unwrap_or(String::new()),
            if let Some(coordinates) = region.coordinates {
                (coordinates.lat.to_string(), coordinates.lon.to_string())
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

    if config.country {
        rows_vec.push(Cell::new(country.as_str()).with_style(Attr::ForegroundColor(color::GREEN)));
    }

    if config.region {
        rows_vec.push(Cell::new(region.as_str()).with_style(Attr::ForegroundColor(color::GREEN)));
    }

    if config.city {
        rows_vec.push(Cell::new(city.as_str()).with_style(Attr::ForegroundColor(color::GREEN)));
    }

    if config.coordinates {
        rows_vec
            .push(Cell::new(lat.as_str()).with_style(Attr::ForegroundColor(color::BRIGHT_GREEN)));
        rows_vec
            .push(Cell::new(lon.as_str()).with_style(Attr::ForegroundColor(color::BRIGHT_GREEN)));
    }

    if config.time_zone {
        rows_vec.push(
            Cell::new(time_zone.as_str()).with_style(Attr::ForegroundColor(color::BRIGHT_MAGENTA)),
        );
    }

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

    if config.risk {
        rows_vec.push(Cell::new(risk.as_str()).with_style(Attr::ForegroundColor(color::RED)));
    }

    if config.tags {
        rows_vec.push(
            Cell::new(risk_tags_str.as_str())
                .with_style(Attr::ForegroundColor(color::BRIGHT_YELLOW)),
        );
    }

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

    Some(Row::new(rows_vec))
}
