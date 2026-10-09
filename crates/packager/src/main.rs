fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--help"] || args.as_slice() == ["-h"] {
        println!("{}", rhso_packager::usage());
        return;
    }
    let result = rhso_packager::parse_args(args)
        .and_then(|options| rhso_packager::run(&options).map(|p| (options, p)));
    match result {
        Ok((options, package)) => {
            println!("Package: {}", options.output.display());
            println!("Entries: {}", package.entries);
            println!("SHA-256: {}", package.sha256);
        }
        Err(message) => {
            eprintln!("Packaging stopped: {message}");
            std::process::exit(1);
        }
    }
}
