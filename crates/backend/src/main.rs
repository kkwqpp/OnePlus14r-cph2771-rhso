fn main() {
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGTERM, libc::SIG_IGN);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let app = rhso::App::new(
        "/data/adb/wallet_diagnostic",
        "/data/adb/tricky_store",
        "/data/adb/modules",
        false,
    );
    let response = rhso::request::execute(&app, &args);
    let json = args.first().is_some_and(|s| s == "request") || args.iter().any(|s| s == "--json");
    if json {
        println!(
            "{}",
            serde_json::to_string(&response).expect("fixed response")
        );
    } else {
        rhso::request::human(&response);
    }
    std::process::exit(rhso::error::exit_code(&response.code));
}
