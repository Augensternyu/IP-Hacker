use crate::config;
use crate::config::Config;
use crate::ip_check::ip_result::{IpResult, RiskTag};
use prettytable::{Attr, Cell, Row, Table, color, format};

pub async fn gen_table(ip_results_vec: &Vec<IpResult>, config: &config::Config) -> Table {
    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    table.set_titles(Row::new(make_table_cells(config)));

    for ip_result in ip_results_vec {
        if let Some(row) = make_table_row(ip_result.clone(), config) {
            table.add_row(row);
        }
    }
    table
}

fn make_table_cells(config: &config::Config) -> Vec<Cell> {
    let mut cells = Vec::new();
    if config.provider {
        cells.push(
            Cell::new("Provider")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        );
    };
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
        )
    }
    if config.country {
        cells.push(
            Cell::new("Country")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        )
    }
    if config.region {
        cells.push(
            Cell::new("Region")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        )
    }
    if config.city {
        cells.push(
            Cell::new("City")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        )
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
        )
    }
    if config.time_zone {
        cells.push(
            Cell::new("Time Zone")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        )
    }
    if config.risk {
        cells.push(
            Cell::new("Risk")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        )
    }
    if config.tags {
        cells.push(
            Cell::new("Tags")
                .with_style(Attr::ForegroundColor(color::YELLOW))
                .with_style(Attr::Bold),
        )
    }
    cells
}

fn make_table_row(ip_result: IpResult, config: &Config) -> Option<Row> {
    let mut rows_vec = Vec::new();

    if !ip_result.success {
        return None;
    }

    if config.provider {
        rows_vec.push(Cell::new(ip_result.provider.as_str()));
    }

    if config.ip {
        let ip = if let Some(ip) = ip_result.ip {
            ip.to_string()
        } else {
            "N/A".to_string()
        };
        rows_vec.push(Cell::new(&ip));
    }

    let (asn, isp) = if let Some(a_s) = ip_result.autonomous_system {
        (a_s.number.to_string(), a_s.name)
    } else {
        ("N/A".to_string(), "N/A".to_string())
    };

    if config.asn {
        rows_vec.push(Cell::new(asn.as_str()));
    }

    if config.isp {
        rows_vec.push(Cell::new(isp.as_str()));
    }

    let (country, region, city, (lat, lon), time_zone) = if let Some(region) = ip_result.region {
        (
            region.country.unwrap_or("N/A".to_string()),
            region.region.unwrap_or("N/A".to_string()),
            region.city.unwrap_or("N/A".to_string()),
            if let Some(coordinates) = region.coordinates {
                (coordinates.lat.to_string(), coordinates.lon.to_string())
            } else {
                ("N/A".to_string(), "N/A".to_string())
            },
            region.time_zone.unwrap_or("N/A".to_string()),
        )
    } else {
        (
            "N/A".to_string(),
            "N/A".to_string(),
            "N/A".to_string(),
            ("N/A".to_string(), "N/A".to_string()),
            "N/A".to_string(),
        )
    };

    if config.country {
        rows_vec.push(Cell::new(country.as_str()));
    }

    if config.region {
        rows_vec.push(Cell::new(region.as_str()));
    }

    if config.city {
        rows_vec.push(Cell::new(city.as_str()));
    }

    if config.coordinates {
        rows_vec.push(Cell::new(lat.as_str()));
        rows_vec.push(Cell::new(lon.as_str()));
    }

    if config.time_zone {
        rows_vec.push(Cell::new(time_zone.as_str()));
    }

    let (risk, tags) = if let Some(risk) = ip_result.risk {
        (
            if let Some(risk) = risk.risk {
                risk.to_string()
            } else {
                "N/A".to_string()
            },
            risk.tags.unwrap_or_default()
        )
    } else {
        ("N/A".to_string(), vec![])
    };

    let mut risk_tags = Vec::new();
    for tag in tags {
        risk_tags.push(match tag {
            RiskTag::Tor => "TOR",
            RiskTag::Proxy => "PROXY",
            RiskTag::Hosting => "HOSTING",
            RiskTag::Relay => "RELAY",
        });
    }
    let risk_tags_str = risk_tags.join(", ");

    if config.risk {
        rows_vec.push(Cell::new(risk.as_str()));
    }

    if config.tags {
        rows_vec.push(Cell::new(risk_tags_str.as_str()));
    }

    Some(Row::new(rows_vec))
}
