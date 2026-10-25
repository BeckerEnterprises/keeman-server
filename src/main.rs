//! KeeMan API server binary.

fn main() -> std::process::ExitCode {
    keeman_server::cli::run()
}
