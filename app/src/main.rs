// Release builds are GUI apps on Windows: no console window alongside the app.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    ghaudit_desktop::run()
}
