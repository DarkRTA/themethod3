fn main() {
    csbindgen::Builder::default()
        .input_extern_file("src/lib.rs")
        .csharp_namespace("TheMethod3")
        .csharp_class_name("TheMethod3")
        .csharp_dll_name("themethod3")
        .generate_csharp_file("bindings/themethod3.cs")
        .unwrap();

    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    cbindgen::Builder::new()
      .with_crate(crate_dir)
      .with_language(cbindgen::Language::C)
      .with_cpp_compat(true)
      .generate()
      .expect("Unable to generate bindings")
      .write_to_file("bindings/themethod3.h");
}
