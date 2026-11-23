fn main() {
    println!("cargo:rerun-if-changed=src/ct.c");
    cc::Build::new().file("src/ct.c").compile("ctshim");
}
