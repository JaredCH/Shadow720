//! Shadow720 — serverless E2EE group app.
//!
//! This is the Android/mobile binary entry point. The desktop binary is
//! `main.rs`; both call into the same [`run`] function so behaviour cannot drift
//! between them.

// Hide the console window on a Windows release build.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    shadow720_lib::run()
}