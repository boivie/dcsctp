#[cxx::bridge]
mod ffi {
    extern "Rust" {
        fn version() -> String;
    }
}

fn version() -> String {
    dcsctp::version().to_string()
}
