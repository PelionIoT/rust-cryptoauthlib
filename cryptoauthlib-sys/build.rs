use cmake;

fn main()
{
    let dst = cmake::Config::new("cryptoauthlib")
                     .no_build_target(true) // Prevent installing in host system directories
                     .define("ATCA_HAL_I2C", "ON")
                     .build();       
    // Below caller LD_FLAGS are defined. First -L then -l
    println!("cargo:rustc-link-search=all={}/build/lib", dst.display());
    println!("cargo:rustc-link-lib=dylib=cryptoauth");
    
    println!("cargo:rustc-cdylib-link-arg=-Wl,-rpath,{}/build/lib",dst.display())
}
