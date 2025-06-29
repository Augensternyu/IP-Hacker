use crate::ip_result::IpResult;
use eframe::egui;
use egui_extras::{Column, TableBuilder};

#[derive(Debug)]
pub struct TableRow {
    pub id: u32,
    pub provider: String,
    pub ip: String,
    pub asn: String,
    pub isp: String,
    pub country: String,
    pub region: String,
    pub city: String,
    pub time_zone: String,
    pub lat: String,
    pub lon: String,
    pub risk_score: String,
    pub tags: String,
}

impl From<IpResult> for TableRow {
    fn from(result: IpResult) -> Self {
        Self {
            id: result.id,
            provider: result.provider,
            ip: {
                if result.ip.to_string() == "0.0.0.0" {
                    String::new()
                } else {
                    result.ip.to_string()
                }
            },
            asn: {
                if result.asn == "0" {
                    String::new()
                } else {
                    result.asn
                }
            },
            isp: result.isp,
            country: result.country,
            region: result.region,
            city: result.city,
            time_zone: result.time_zone,
            lat: result.lat,
            lon: result.lon,
            risk_score: result.risk_score,
            tags: result.tags,
        }
    }
}

pub struct TableApp {
    pub rows: Vec<TableRow>,
    pub sort_by: Option<(usize, bool)>,
}

impl TableApp {
    pub fn update_sort(&mut self, column_index: usize) {
        if let Some((current_col, ascending)) = self.sort_by {
            if current_col == column_index {
                self.sort_by = Some((column_index, !ascending));
            } else {
                self.sort_by = Some((column_index, true));
            }
        } else {
            self.sort_by = Some((column_index, true));
        }
    }
}

pub fn build_table(ui: &mut egui::Ui, table_app: &mut TableApp) {
    if let Some((column_index, ascending)) = table_app.sort_by {
        table_app.rows.sort_by(|a, b| {
            let ordering = match column_index {
                0 => a.id.cmp(&b.id),
                1 => a.provider.cmp(&b.provider),
                2 => a.ip.cmp(&b.ip),
                3 => a.asn.cmp(&b.asn),
                4 => a.isp.cmp(&b.isp),
                5 => a.country.cmp(&b.country),
                6 => a.region.cmp(&b.region),
                7 => a.city.cmp(&b.city),
                8 => a.time_zone.cmp(&b.time_zone),
                9 => a.lat.cmp(&b.lat),
                10 => a.lon.cmp(&b.lon),
                11 => a.risk_score.cmp(&b.risk_score),
                12 => a.tags.cmp(&b.tags),
                _ => std::cmp::Ordering::Equal,
            };
            if ascending {
                ordering
            } else {
                ordering.reverse()
            }
        });
    }

    let table = TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::auto().resizable(true))
        .column(Column::auto().resizable(true))
        .column(Column::auto().resizable(true))
        .column(Column::auto().resizable(true))
        .column(Column::auto().resizable(true))
        .column(Column::auto().resizable(true))
        .column(Column::auto().resizable(true))
        .column(Column::auto().resizable(true))
        .column(Column::auto().resizable(true))
        .column(Column::auto().resizable(true))
        .column(Column::auto().resizable(true))
        .column(Column::auto().resizable(true))
        .column(Column::auto().resizable(true))
        .min_scrolled_height(400.0);

    table
        .header(20.0, |mut header| {
            header.col(|ui| {
                if ui.button("ID").clicked() {
                    table_app.update_sort(0);
                }
            });
            header.col(|ui| {
                if ui.button("Provider").clicked() {
                    table_app.update_sort(1);
                }
            });
            header.col(|ui| {
                if ui.button("IP").clicked() {
                    table_app.update_sort(2);
                }
            });
            header.col(|ui| {
                if ui.button("ASN").clicked() {
                    table_app.update_sort(3);
                }
            });
            header.col(|ui| {
                if ui.button("ISP").clicked() {
                    table_app.update_sort(4);
                }
            });
            header.col(|ui| {
                if ui.button("Country").clicked() {
                    table_app.update_sort(5);
                }
            });
            header.col(|ui| {
                if ui.button("Region").clicked() {
                    table_app.update_sort(6);
                }
            });
            header.col(|ui| {
                if ui.button("City").clicked() {
                    table_app.update_sort(7);
                }
            });
            header.col(|ui| {
                if ui.button("Time Zone").clicked() {
                    table_app.update_sort(8);
                }
            });
            header.col(|ui| {
                if ui.button("Lat").clicked() {
                    table_app.update_sort(9);
                }
            });
            header.col(|ui| {
                if ui.button("Lon").clicked() {
                    table_app.update_sort(10);
                }
            });
            header.col(|ui| {
                if ui.button("Risk Score").clicked() {
                    table_app.update_sort(11);
                }
            });

            header.col(|ui| {
                if ui.button("Risk Tags").clicked() {
                    table_app.update_sort(12);
                }
            });
        })
        .body(|mut body| {
            for row_data in &table_app.rows {
                body.row(30.0, |mut row| {
                    // --- 修改点 4: 渲染3个单元格，与表头和数据匹配 ---
                    row.col(|ui| {
                        ui.label(row_data.id.to_string());
                    });
                    row.col(|ui| {
                        ui.label(&row_data.provider);
                    });
                    row.col(|ui| {
                        ui.label(row_data.ip.to_string());
                    });
                    row.col(|ui| {
                        ui.label(row_data.asn.to_string());
                    });
                    row.col(|ui| {
                        ui.label(row_data.isp.to_string());
                    });
                    row.col(|ui| {
                        ui.label(row_data.country.to_string());
                    });
                    row.col(|ui| {
                        ui.label(row_data.region.to_string());
                    });
                    row.col(|ui| {
                        ui.label(row_data.city.to_string());
                    });
                    row.col(|ui| {
                        ui.label(row_data.time_zone.to_string());
                    });
                    row.col(|ui| {
                        ui.label(row_data.lat.to_string());
                    });
                    row.col(|ui| {
                        ui.label(row_data.lon.to_string());
                    });
                    row.col(|ui| {
                        ui.label(row_data.risk_score.to_string());
                    });
                    row.col(|ui| {
                        ui.label(row_data.tags.to_string());
                    });
                });
            }
        });
}
