fn main() {
    println!("cargo:rerun-if-changed=bpf/egresso.bpf.c");

    let out = std::env::var("OUT_DIR").unwrap();
    let obj = format!("{out}/egresso.bpf.o");
    let status = std::process::Command::new("clang")
        .args([
            "-O2",
            "-g",
            "-target",
            "bpf",
            "-c",
            "bpf/egresso.bpf.c",
            "-o",
            &obj,
            "-fno-stack-protector",
            "-Wall",
            "-Wno-unused-value",
            "-Wno-pointer-sign",
        ])
        .status()
        .expect("clang is required to build the BPF object (apt install clang)");
    if !status.success() {
        panic!("clang failed to compile bpf/egresso.bpf.c");
    }
}
