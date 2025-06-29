// src/main.rs

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![allow(rustdoc::missing_crate_level_docs)]

mod ip_result;
mod table;

use crate::ip_result::{IpResult, get_result_stream};
use crate::table::{TableApp, TableRow, build_table};
use eframe::egui;
use eframe::egui::{Align2, Layout, RichText, ScrollArea};
use egui_file::FileDialog;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};

struct IPHacker {
    ip: String,
    msg: String,
    table: TableApp,
    is_testing: bool,
    result_receiver: Option<Receiver<IpResult>>,
    binary_file: PathBuf,
    open_binary_file_dialog: Option<FileDialog>,
}

impl Default for IPHacker {
    fn default() -> Self {
        Self {
            ip: "".to_string(),
            msg: String::default(),
            table: TableApp {
                rows: vec![],
                sort_by: None,
            },
            is_testing: false,
            result_receiver: None,
            binary_file: {
                if cfg!(target_os = "windows") {
                    PathBuf::from("./IP-Hacker.exe")
                } else {
                    PathBuf::from("./IP-Hacker")
                }
            },
            open_binary_file_dialog: None,
        }
    }
}

impl eframe::App for IPHacker {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(rx) = &self.result_receiver {
            while let Ok(result) = rx.try_recv() {
                self.msg
                    .push_str(&format!("Received: {}\n", result.provider));
                if result.success {
                    self.table.rows.push(TableRow::from(result));
                } else {
                    self.msg
                        .push_str(&format!("❌ {} Error: {}\n", result.provider, result.error));
                }
            }

            if let Err(mpsc::TryRecvError::Disconnected) = rx.try_recv() {
                self.msg.push_str("✅ Test finished.\n");
                self.is_testing = false;
                self.result_receiver = None;
            }
        }

        if self.is_testing {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("IP-Hacker");

            egui::Area::new("link_area".into())
                .anchor(Align2::RIGHT_TOP, egui::vec2(-8.0, 8.0))
                .show(ctx, |ui| {
                    ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.hyperlink_to(
                            RichText::new("View My Github Page")
                                .small()
                                .weak(),
                            "https://github.com/GenshinMinecraft",
                        );
                    });
                });

            ui.horizontal(|ui| {
                let ip_label = ui.label("Set IP: ");
                ui.text_edit_singleline(&mut self.ip)
                    .labelled_by(ip_label.id);

                if ui.button("Choose the exec binary").clicked() {
                    let mut dialog = FileDialog::open_file(Some(self.binary_file.clone()));
                    dialog.open();
                    self.open_binary_file_dialog = Some(dialog);
                }

                if let Some(dialog) = &mut self.open_binary_file_dialog {
                    if dialog.show(ctx).selected() {
                        if let Some(file) = dialog.path() {
                            self.binary_file = file.to_path_buf();
                        }
                    }
                }
            });

            let start_button_response =
                ui.add_enabled(!self.is_testing, egui::Button::new("Start Test"));

            if self.is_testing {
                start_button_response
                    .clone()
                    .on_hover_text("A test is already in progress.");
            }

            if start_button_response.clicked() {
                self.table.rows.clear();
                self.msg.clear();
                self.msg.push_str("🚀 Starting test...\n");

                match get_result_stream(&self.binary_file, &self.ip) {
                    Ok(rx) => {
                        self.result_receiver = Some(rx);
                        self.is_testing = true;
                    }
                    Err(e) => {
                        self.msg.push_str(&format!("❌ Error: {}\n", e));
                    }
                }
            }

            egui::Frame::group(ui.style()).show(ui, |ui| {
                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .stick_to_bottom(true)
                    .max_height(100.0)
                    .show(ui, |ui| {
                        ui.label(&self.msg);
                    });
            });

            ui.add_space(16.0);
            ui.separator();
            ui.heading("Results Table");

            build_table(ui, &mut self.table);

            egui::TopBottomPanel::bottom("footer_panel").show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(5.0);
                    ui.label(RichText::new("Powered by rust & egui").size(12.0));
                    ui.hyperlink_to(
                        "WE LOVE OPEN-SOURCE | Github Link",
                        "https://github.com/rsbench/IP-Hacker",
                    );
                    ui.add_space(5.0);
                });
            });
        });
    }
}

fn main() -> eframe::Result {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Debug)
        .with_colors(true)
        .init()
        .unwrap();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("IP-Hacker GUI")
            .with_decorations(true)
            .with_resizable(true)
            .with_active(true),
        ..Default::default()
    };
    eframe::run_native(
        "IP-Hacker GUI",
        options,
        Box::new(|cc| {
            let mut fonts = egui::FontDefinitions::default();

            fonts.font_data.insert(
                "my_font".to_owned(),
                Arc::from(egui::FontData::from_static(include_bytes!(
                    "../assets/SourceHanSansCN-Medium.ttf"
                ))),
            );

            fonts
                .families
                .entry(egui::FontFamily::Proportional)
                .or_default()
                .insert(0, "my_font".to_owned());

            fonts
                .families
                .entry(egui::FontFamily::Monospace)
                .or_default()
                .insert(0, "my_font".to_owned());

            cc.egui_ctx.set_fonts(fonts);
            catppuccin_egui::set_theme(&cc.egui_ctx, catppuccin_egui::MOCHA);
            Ok(Box::<IPHacker>::default())
        }),
    )
}
