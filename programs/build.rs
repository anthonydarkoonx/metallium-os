fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    // METALLIUM_PIE=1: the position-independent build (see the Makefile's `programs`); each program carries its own name (-soname)
    let pie = std::env::var_os("METALLIUM_PIE").is_some();
    println!("cargo:rustc-link-arg=-T{dir}/{}", if pie { "link-pie.ld" } else { "link.ld" });
    if pie {
        for e in std::fs::read_dir(format!("{dir}/src/bin")).unwrap().flatten() {
            if let Some(n) = e.file_name().to_str().and_then(|n| n.strip_suffix(".rs")) {
                println!("cargo:rustc-link-arg-bin={n}=-soname={n}");
            }
        }
        // (the network programs are built from the networking repository, see Cargo.toml)
        for n in ["nettest", "netcheck", "fetch"] {
            println!("cargo:rustc-link-arg-bin={n}=-soname={n}");
        }
    }
    println!("cargo:rerun-if-changed=link.ld");
    println!("cargo:rerun-if-changed=link-pie.ld");
    println!("cargo:rerun-if-changed=src/bin");
    println!("cargo:rerun-if-changed=../../metallium-networking-userspace/programs");
    println!("cargo:rerun-if-changed=../../metallium-networking-userspace/client");
    println!("cargo:rerun-if-env-changed=METALLIUM_PIE");
}
