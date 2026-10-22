fn main() {
    let dst = cmake::Config::new("cryptoauthlib")
        .no_build_target(true) // Prevent installing in host system directories
        .define("ATCA_BUILD_SHARED_LIBS", "0") // Build CAL as a static library
        .define("ATCA_HAL_I2C", "ON") // Include i2c support
        .define("ATCA_USE_ATCAB_FUNCTIONS", "ON") // build atcab_* wrappers
        .build();
    // Below caller LD_FLAGS are defined. First -L then -l
    println!("cargo:rustc-link-search=native={}/build/lib", dst.display());
    println!("cargo:rustc-link-lib=static=cryptoauth");
}
