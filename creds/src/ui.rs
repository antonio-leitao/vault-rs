use indicatif::{ProgressBar, ProgressStyle};
use std::error::Error;
use std::time::Duration;

pub struct StatusUI;

impl StatusUI {
    // Status symbols
    pub const SUCCESS: &'static str = "✓";
    pub const WARNING: &'static str = "⚠";
    pub const ERROR: &'static str = "✗";
    pub const CAUSE: &'static str = "└─";
    pub const INFO: &'static str = "•";

    pub fn success(message: &str) {
        println!("   {} {}", Self::SUCCESS, message);
    }

    pub fn warning(message: &str) {
        println!("   {} {}", Self::WARNING, message);
    }

    pub fn error(message: &str) {
        println!("   {} {}", Self::ERROR, message);
    }

    pub fn info(message: &str) {
        println!("   {} {}", Self::INFO, message);
    }

    /// Renders a structured error, including its source chain.
    /// This is generic over any type that implements `std::error::Error`.
    pub fn render_error<E: Error>(err: E) {
        // Print the primary error message using the existing style
        println!("      {} {}", Self::ERROR, err);

        // Iterate through the source chain and print each cause
        let mut source = err.source();
        while let Some(cause) = source {
            println!("        {} Caused by: {}", Self::CAUSE, cause);
            source = cause.source();
        }
    }

    // Simple spinner
    pub fn spinner(message: &str) -> ProgressBar {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::with_template("   {spinner} {msg}")
                .unwrap()
                .tick_strings(&["|", "/", "-", "\\"]),
        );
        pb.set_message(message.to_string());
        pb.enable_steady_tick(Duration::from_millis(100));
        pb
    }

    // Finish spinner with status
    pub fn finish_spinner_success(pb: ProgressBar, message: &str) {
        pb.finish_and_clear();
        Self::success(message);
    }

    pub fn finish_spinner_error(pb: ProgressBar, message: &str) {
        pb.finish_and_clear();
        Self::error(message);
    }

    pub fn finish_spinner_warning(pb: ProgressBar, message: &str) {
        pb.finish_and_clear();
        Self::warning(message);
    }

    pub fn finish_spinner_info(pb: ProgressBar, message: &str) {
        pb.finish_and_clear();
        Self::info(message);
    }

    // Format file size utility
    pub fn format_file_size(bytes: usize) -> String {
        if bytes > 1024 * 1024 * 1024 {
            format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
        } else if bytes > 1024 * 1024 {
            format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
        } else if bytes > 1024 {
            format!("{:.2} KB", bytes as f64 / 1024.0)
        } else {
            format!("{} bytes", bytes)
        }
    }
}
