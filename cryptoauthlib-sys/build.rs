use cmake;

fn main()
{
    let dst = cmake::Config::new("cryptoauthlib")
                     .build_target("") // Prevent installing in host system directories
                     .define("ATCA_HAL_I2C", "ON")
                     .build();       
    // Below caller LD_FLAGS are defined. First -L then -l
    println!("cargo:rustc-link-search=native={}/build/lib", dst.display());
    println!("cargo:rustc-link-lib=dylib=cryptoauth");    
}
