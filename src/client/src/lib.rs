mod message;
mod app;
mod file;
mod key;
mod account;
mod socket;
mod session;
mod support;

use fern::Dispatch;
use chrono::Local;

use eframe;
use crate::app::AppState;

fn setup_logger() -> Result<(), fern::InitError> {
    Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                Local::now().format("[%Y-%m-%d %H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(log::LevelFilter::Info)
        .chain(std::io::stdout())
        .apply()?;
    Ok(())
}

pub fn start() -> eframe::Result<()> {
    setup_logger().expect("Failed to setup logger");
    
    eframe::run_native(
        "End-to-End Encrypted Chat", 
        eframe::NativeOptions::default(), 
        Box::new(|_| Ok(Box::new(AppState::new())))
    )
}