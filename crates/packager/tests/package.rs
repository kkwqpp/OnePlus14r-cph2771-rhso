use rhso_packager::{
    Options, REQUIRED, STRONGBOX_OVERLAY, archive, collect, embed_file, embedded_wasm, parse_args,
    run, validate_elf,
};
use std::{
    fs,
    io::{Cursor, Read},
    path::Path,
};
use zip::{DateTime, ZipArchive};

fn put16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}
fn elf() -> Vec<u8> {
    let mut b = vec![0; 1024];
    b[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    put16(&mut b, 16, 3);
    put16(&mut b, 18, 183);
    put32(&mut b, 20, 1);
    put64(&mut b, 24, 0x300);
    put64(&mut b, 32, 64);
    put16(&mut b, 52, 64);
    put16(&mut b, 54, 56);
    put16(&mut b, 56, 3);
    put32(&mut b, 64, 1);
    put32(&mut b, 68, 5);
    put64(&mut b, 96, 1024);
    put64(&mut b, 104, 1024);
    put64(&mut b, 112, 16384);
    let interp = b"/system/bin/linker64\0";
    let h = 120;
    put32(&mut b, h, 3);
    put64(&mut b, h + 8, 384);
    put64(&mut b, h + 32, interp.len() as u64);
    b[384..384 + interp.len()].copy_from_slice(interp);
    let h = 176;
    put32(&mut b, h, 2);
    put64(&mut b, h + 8, 512);
    put64(&mut b, h + 32, 32);
    put64(&mut b, 512, 0x6ffffffb);
    put64(&mut b, 520, 0x08000000);
    b
}
fn fixture(root: &Path) -> Options {
    let module = root.join("module");
    for name in REQUIRED {
        let p = module.join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        let bytes: Vec<u8> = match *name {
            n if n == STRONGBOX_OVERLAY => b"<permissions>
  <feature name=\"android.hardware.keystore.app_attest_key\" />
</permissions>
"
            .to_vec(),
            "module.prop" => b"id=wallet_diagnostic\nversion=v0.3.0\nversionCode=4\n".to_vec(),
            "webroot/rhso_webui_bg.wasm" => b"\0asm\x01\0\0\0".to_vec(),
            _ => b"synthetic public fixture\n".to_vec(),
        };
        fs::write(p, bytes).unwrap();
    }
    let backend = root.join("walletdiag");
    fs::write(&backend, elf()).unwrap();
    Options {
        backend,
        module,
        output: root.join("release.zip"),
    }
}

#[test]
fn executable_gnu_stack_is_rejected() {
    let mut bytes = elf();
    put16(&mut bytes, 56, 4);
    put32(&mut bytes, 232, 0x6474e551);
    put32(&mut bytes, 236, 6);
    validate_elf(&bytes).unwrap();
    put32(&mut bytes, 236, 7);
    assert!(validate_elf(&bytes).is_err());
}

#[test]
fn elf_requires_android_pie_interpreter_and_every_load_alignment() {
    validate_elf(&elf()).unwrap();
    let changes: Vec<(usize, Vec<u8>)> = vec![
        (0, b"NOPE".to_vec()),
        (4, vec![1]),
        (5, vec![2]),
        (16, 2u16.to_le_bytes().to_vec()),
        (18, 62u16.to_le_bytes().to_vec()),
        (112, 4096u64.to_le_bytes().to_vec()),
        (80, 1u64.to_le_bytes().to_vec()),
        (24, 2000u64.to_le_bytes().to_vec()),
        (384, b"x".to_vec()),
        (520, 0u64.to_le_bytes().to_vec()),
        (208, 16u64.to_le_bytes().to_vec()),
        (68, 7u32.to_le_bytes().to_vec()),
        (32, u64::MAX.to_le_bytes().to_vec()),
        (96, u64::MAX.to_le_bytes().to_vec()),
        (54, 55u16.to_le_bytes().to_vec()),
    ];
    for (off, bytes) in changes {
        let mut b = elf();
        b[off..off + bytes.len()].copy_from_slice(&bytes);
        assert!(
            validate_elf(&b).is_err(),
            "accepted malformed ELF field at {off}"
        );
    }
    let mut b = elf();
    put16(&mut b, 56, 4);
    b.copy_within(64..120, 232);
    put64(&mut b, 280, 4096);
    assert!(
        validate_elf(&b).is_err(),
        "all LOAD segments require alignment"
    );
}
#[test]
fn known_assets_only_and_derived_wasm_cannot_ship_stale_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let o = fixture(temp.path());
    fs::write(
        o.module.join("webroot/rhso_webui_bytes.js"),
        "PRIVATE_OLD_BYTE_SENTINEL",
    )
    .unwrap();
    fs::write(
        o.module.join("webroot/rhso_webui.d.ts"),
        "PRIVATE_TYPE_SENTINEL",
    )
    .unwrap();
    fs::write(
        o.module.join("licenses/Go-BSD-3-Clause.txt"),
        "old runtime notice",
    )
    .unwrap();
    let files = collect(&o.module, &o.backend).unwrap();
    assert!(
        !files
            .keys()
            .any(|p| p.ends_with(".d.ts") || p.contains("Go-BSD"))
    );
    assert_eq!(
        files["webroot/rhso_webui_bytes.js"],
        embedded_wasm(b"\0asm\x01\0\0\0").unwrap()
    );
    assert!(
        !files
            .values()
            .any(|v| v.windows(7).any(|w| w == b"PRIVATE"))
    );
    fs::write(o.module.join("keybox.xml"), "PRIVATE_KEY_SENTINEL").unwrap();
    assert!(collect(&o.module, &o.backend).is_err());
    assert!(!o.output.exists());
}
#[test]
fn missing_assets_crlf_wrong_identity_and_invalid_wasm_are_rejected() {
    for (case, bytes) in [
        ("action.sh", b"echo fixture\r\n".as_slice()),
        (
            "module.prop",
            b"id=wallet_diagnostic\nid=wrong\nversion=v0.3.0\nversionCode=4\n",
        ),
        ("webroot/rhso_webui_bg.wasm", b"not wasm"),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let o = fixture(temp.path());
        fs::write(o.module.join(case), bytes).unwrap();
        assert!(run(&o).is_err());
        assert!(!o.output.exists());
    }
    let temp = tempfile::tempdir().unwrap();
    let o = fixture(temp.path());
    fs::remove_file(o.module.join("licenses/Rust-THIRD-PARTY-NOTICES.txt")).unwrap();
    assert!(run(&o).is_err());
    assert!(!o.output.exists());
}
#[test]
fn archives_repeat_exactly_with_fixed_order_modes_dates_and_checksum() {
    let temp = tempfile::tempdir().unwrap();
    let o = fixture(temp.path());
    let a = run(&o).unwrap();
    let b = run(&o).unwrap();
    assert_eq!(a.bytes, b.bytes);
    assert_eq!(a.sha256, b.sha256);
    assert_eq!(fs::read(&o.output).unwrap(), a.bytes);
    assert_eq!(
        fs::read_to_string(o.output.with_extension("zip.sha256")).unwrap(),
        format!("{}  release.zip\n", a.sha256)
    );
    let mut zip = ZipArchive::new(Cursor::new(a.bytes)).unwrap();
    let mut names = Vec::new();
    for i in 0..zip.len() {
        let entry = zip.by_index(i).unwrap();
        names.push(entry.name().to_owned());
        assert_eq!(
            entry.last_modified(),
            Some(DateTime::from_date_and_time(2000, 1, 1, 0, 0, 0).unwrap())
        );
        assert_eq!(
            entry.unix_mode().unwrap() & 0o777,
            if entry.name() == "bin/walletdiag" || entry.name().ends_with(".sh") {
                0o755
            } else {
                0o644
            }
        );
    }
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
    assert_eq!(names.len(), REQUIRED.len() + 2);
    let mut bytes = String::new();
    zip.by_name("webroot/rhso_webui_bytes.js")
        .unwrap()
        .read_to_string(&mut bytes)
        .unwrap();
    assert!(bytes.contains("export const wasmBase64 = \"AGFzbQEAAAA=\";"));
}
#[test]
fn output_cannot_overwrite_sources_or_unsafe_existing_sidecar() {
    let temp = tempfile::tempdir().unwrap();
    let mut o = fixture(temp.path());
    o.output = o.module.join("release.zip");
    assert!(run(&o).is_err());
    o.output = temp.path().join("release.zip");
    fs::create_dir(o.output.with_extension("zip.sha256")).unwrap();
    fs::write(&o.output, b"prior archive").unwrap();
    assert!(run(&o).is_err());
    assert_eq!(fs::read(&o.output).unwrap(), b"prior archive");
    for name in [
        ".hidden.zip",
        "line\nbreak.zip",
        "archive.tar",
        "out space.zip",
    ] {
        o.output = temp.path().join(name);
        assert!(run(&o).is_err());
    }
}
#[test]
fn unknown_directories_and_special_entries_do_not_enter_archive() {
    let temp = tempfile::tempdir().unwrap();
    let o = fixture(temp.path());
    fs::create_dir(o.module.join("private-inbox")).unwrap();
    assert!(run(&o).is_err());
}
#[test]
fn cli_requires_explicit_paths_and_rejects_unknown_duplicate_flags() {
    let parse = |args: &[&str]| parse_args(args.iter().map(|s| s.to_string()));
    assert!(parse(&[]).is_err());
    for args in [
        vec!["--backend", "a"],
        vec!["--backend", "a", "--output", "b", "--output", "c"],
        vec!["--backend", "--output", "b"],
        vec!["--backend", "a", "--output", "b", "--fetch", "c"],
    ] {
        assert!(parse(&args).is_err());
    }
    let o = parse(&["--backend", "a", "--output", "b"]).unwrap();
    assert_eq!(o.module, Path::new("module"));
}
#[cfg(unix)]
#[test]
fn symlink_sources_and_ancestors_are_rejected() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let o = fixture(temp.path());
    let asset = o.module.join("webroot/app.js");
    fs::remove_file(&asset).unwrap();
    symlink(&o.backend, &asset).unwrap();
    assert!(run(&o).is_err());
    fs::remove_file(asset).unwrap();
    fs::write(o.module.join("webroot/app.js"), b"fixture").unwrap();
    let alias = temp.path().join("alias");
    symlink(&o.module, &alias).unwrap();
    assert!(collect(&alias, &o.backend).is_err());
}
#[cfg(windows)]
#[test]
fn junction_sources_and_ancestors_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let o = fixture(temp.path());
    let alias = temp.path().join("alias");
    let status = std::process::Command::new("cmd")
        .arg("/c")
        .arg("mklink")
        .arg("/J")
        .arg(&alias)
        .arg(&o.module)
        .status()
        .unwrap();
    assert!(status.success());
    assert!(collect(&alias, &o.backend).is_err());
    fs::remove_dir(alias).unwrap();
}
#[test]
fn direct_archive_is_deterministic_independent_of_input_insertion_order() {
    let a = archive([(String::from("z"), vec![3]), (String::from("a"), vec![1])].into()).unwrap();
    let b = archive([(String::from("a"), vec![1]), (String::from("z"), vec![3])].into()).unwrap();
    assert_eq!(a.bytes, b.bytes);
}
#[test]
fn source_byte_helper_uses_identical_generator_and_guards_its_output() {
    let temp = tempfile::tempdir().unwrap();
    let wasm = temp.path().join("ui.wasm");
    let out = temp.path().join("webroot/rhso_webui_bytes.js");
    let data = b"\0asm\x01\0\0\0";
    fs::write(&wasm, data).unwrap();
    embed_file(&wasm, &out).unwrap();
    assert_eq!(fs::read(&out).unwrap(), embedded_wasm(data).unwrap());
    embed_file(&wasm, &out).unwrap();
    assert!(embed_file(&wasm, &temp.path().join("walletdiag")).is_err());
    fs::write(&wasm, b"corrupt").unwrap();
    assert!(embed_file(&wasm, &out).is_err());
    assert_eq!(fs::read(&out).unwrap(), embedded_wasm(data).unwrap());
}
#[test]
fn strongbox_overlay_must_drop_strongbox_and_keep_app_attest_key() {
    let temp = tempfile::tempdir().unwrap();
    let o = fixture(temp.path());
    let p = o.module.join(STRONGBOX_OVERLAY);
    fs::write(
        &p,
        "<permissions>\n  <feature name=\"android.hardware.strongbox_keystore\" version=\"300\"/>\n  <feature name=\"android.hardware.keystore.app_attest_key\" />\n</permissions>\n",
    )
    .unwrap();
    assert!(run(&o).is_err());
    fs::write(&p, "<permissions>\n</permissions>\n").unwrap();
    assert!(run(&o).is_err());
    assert!(!o.output.exists());
}
