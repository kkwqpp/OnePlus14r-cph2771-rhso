use std::path::PathBuf;
fn run(args: Vec<String>) -> Result<(), String> {
    let mut input = None;
    let mut output = None;
    let mut it = args.into_iter();
    while let Some(flag) = it.next() {
        let slot = match flag.as_str() {
            "--input" => &mut input,
            "--output" => &mut output,
            _ => return Err("Unsupported byte-asset argument.".into()),
        };
        if slot.is_some() {
            return Err("Duplicate byte-asset argument.".into());
        }
        let value = it
            .next()
            .filter(|s| !s.is_empty() && !s.starts_with("--"))
            .ok_or("Byte-asset argument needs a path.")?;
        *slot = Some(PathBuf::from(value));
    }
    rhso_packager::embed_file(
        &input.ok_or("--input is required.")?,
        &output.ok_or("--output is required.")?,
    )
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--help"] || args.as_slice() == ["-h"] {
        println!("Usage: rhso-embed-wasm --input WASM --output PATH/rhso_webui_bytes.js");
        return;
    }
    match run(args) {
        Ok(()) => println!("Embedded WASM asset generated."),
        Err(message) => {
            eprintln!("WASM embedding stopped: {message}");
            std::process::exit(1);
        }
    }
}
