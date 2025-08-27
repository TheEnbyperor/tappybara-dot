fn main() {
    println!("cargo:rustc-link-arg-bins=-Tlinkall.x");
    patch_crate::run().expect("Failed while patching");

    bindings().unwrap();
    asn().unwrap();
}

fn asn() -> Result<(), Box<dyn std::error::Error>> {
    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR")?);

    rasn_compiler::Compiler::<rasn_compiler::prelude::RasnBackend, _>::new_with_config(
        rasn_compiler::prelude::RasnConfig {
            generate_from_impls: true,
            no_std_compliant_bindings: true,
            ..Default::default()
        },
    )
    .add_asn_sources_by_path(
        vec![
            std::path::PathBuf::from("asn1/vas.asn"),
            std::path::PathBuf::from("asn1/config.asn"),
        ]
        .iter(),
    )
    .set_output_mode(rasn_compiler::OutputMode::SingleFile(
        out_path.join("asn.rs"),
    ))
    .compile()?;

    Ok(())
}

fn bindings() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::ffi::OsStrExt;

    let linker = match std::env::var("TARGET")?.as_ref() {
        "xtensa-esp32-none-elf" => {
            std::env::var("RUSTC_LINKER").unwrap_or("xtensa-esp32-elf-ld".to_string())
        }
        "xtensa-esp8266-none-elf" => {
            std::env::var("RUSTC_LINKER").unwrap_or("xtensa-lx106-elf-ld".to_string())
        }
        target => {
            println!(
                "cargo:warning=Generating ESP IDF bindings for target '{}' it not supported.",
                target
            );
            return Ok(());
        }
    };

    let sysroot = std::process::Command::new(linker)
        .arg("--print-sysroot")
        .output()
        .map(|mut output| {
            output.stdout.pop();
            std::path::PathBuf::from(std::ffi::OsStr::from_bytes(&output.stdout))
                .canonicalize()
                .expect("failed to canonicalize sysroot")
        })
        .expect("failed getting sysroot");

    let compiler = sysroot.join("../bin/xtensa-esp32-elf-gcc");
    let ar = sysroot.join("../bin/xtensa-esp32-elf-ar");
    let headers = sysroot.join("include");

    std::process::Command::new(compiler)
        .arg("-c")
        .arg("micro-ecc/uECC.c")
        .arg("-o")
        .arg("build/uECC.o")
        .arg("-mlongcalls")
        .arg("-Ofast")
        .arg("-DuECC_SUPPORTS_secp160r1=0")
        .arg("-DuECC_SUPPORTS_secp192r1=0")
        .arg("-DuECC_SUPPORTS_secp224r1=0")
        .arg("-DuECC_SUPPORTS_secp256r1=1")
        .arg("-DuECC_SUPPORTS_secp256k1=0")
        .arg("-DuECC_SQUARE_FUNC=1")
        .arg("-DuECC_WORD_SIZE=4")
        .status()
        .expect("failed to compile micro-ecc");

    std::process::Command::new(ar)
        .arg("rcs")
        .arg("build/libuECC.a")
        .arg("build/uECC.o")
        .status()
        .expect("failed to archive micro-ecc");

    let micro_ecc_bindings = bindgen::Builder::default()
        .use_core()
        .default_enum_style(bindgen::EnumVariation::Rust {
            non_exhaustive: false,
        })
        .header("micro-ecc/uECC.h")
        .clang_arg("-D__bindgen")
        .clang_arg("-DuECC_SUPPORTS_secp160r1=0")
        .clang_arg("-DuECC_SUPPORTS_secp192r1=0")
        .clang_arg("-DuECC_SUPPORTS_secp224r1=0")
        .clang_arg("-DuECC_SUPPORTS_secp256r1=1")
        .clang_arg("-DuECC_SUPPORTS_secp256k1=0")
        .clang_arg("-DuECC_WORD_SIZE=4")
        .clang_arg("-DuECC_SQUARE_FUNC=1")
        .clang_args(&["-target", "xtensa"])
        .clang_args(&["-x", "c"]);

    let wolf_ssl_bindings = bindgen::Builder::default()
        .use_core()
        .default_enum_style(bindgen::EnumVariation::Rust {
            non_exhaustive: false,
        })
        .header("user_settings.h")
        .header("wolfssl-xtensa/include/wolfssl/ssl.h")
        .header("wolfssl-xtensa/include/wolfssl/error-ssl.h")
        .clang_arg("-Iwolfssl-xtensa/include")
        .clang_arg(format!("-I{}", headers.to_string_lossy()))
        .clang_arg("-D__bindgen")
        .clang_args(&["-target", "xtensa"])
        .clang_args(&["-x", "c"]);

    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR")?);

    micro_ecc_bindings
        .generate()
        .expect("Failed to generate uECC bindings")
        .write_to_file(out_path.join("micro_ecc_bindings.rs"))?;
    wolf_ssl_bindings
        .generate()
        .expect("Failed to generate wolfSSL bindings")
        .write_to_file(out_path.join("wolf_ssl_bindings.rs"))?;

    println!("cargo:rustc-link-search=native=build");
    println!("cargo:rustc-link-search=native=wolfssl-xtensa/lib");
    println!("cargo:rustc-link-lib=static=uECC");
    println!("cargo:rustc-link-lib=static=wolfssl");

    Ok(())
}
