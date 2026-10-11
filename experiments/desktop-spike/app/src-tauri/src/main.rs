#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    ciphermoth_desktop_spike_lib::LAUNCHED.get_or_init(std::time::Instant::now);
    ciphermoth_desktop_spike_lib::run()
}
