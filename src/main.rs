#![windows_subsystem = "windows"]
use std::process::ExitCode;

fn main() -> ExitCode {
    // args_os: a non-Unicode argument is a usage error, never a panic.
    let mut args: Vec<String> = Vec::new();
    for a in std::env::args_os() {
        match a.into_string() {
            Ok(s) => args.push(s),
            Err(bad) => {
                mpdbx::cli::attach_console();
                eprintln!(
                    "mpdbx: argument is not valid Unicode: {}",
                    bad.to_string_lossy()
                );
                return ExitCode::from(2);
            }
        }
    }
    if args.len() > 1 && args[1] != "open" {
        mpdbx::cli::attach_console();
        return mpdbx::cli::run(args);
    }
    let preload = args.get(2).map(std::path::PathBuf::from);
    // optional: mpdbx open <path> --tab findings|timeline|files|evidence
    let start_tab = args.iter().position(|a| a == "--tab").and_then(|i| args.get(i + 1)).map(|t| match t.to_ascii_lowercase().as_str() {
        "timeline" => mpdbx::ui::app::Tab::Timeline,
        "artifacts" | "files" => mpdbx::ui::app::Tab::Artifacts,
        "evidence" => mpdbx::ui::app::Tab::Evidence,
        _ => mpdbx::ui::app::Tab::Findings,
    });
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("mpdbx — MpEngineDB Explorer")
            .with_inner_size([1440.0, 900.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };
    let r = eframe::run_native(
        "mpdbx",
        options,
        Box::new(move |_cc| {
            Ok(Box::new(mpdbx::ui::app::EframeApp(
                {
                    let mut a = mpdbx::ui::app::App::new(preload);
                    if let Some(t) = start_tab {
                        a.tab = t;
                    }
                    a
                },
            )))
        }),
    );
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
