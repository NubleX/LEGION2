use std::process::Command;
use std::path::Path;

fn main() {
    // Download required binaries before building
    download_binaries();
    
    tauri_build::build();
}

fn download_binaries() {
    let script_path = Path::new("../scripts/setup-binaries.cjs");
    
    if script_path.exists() {
        println!("cargo:rerun-if-changed=../scripts/setup-binaries.cjs");
        println!("cargo:rerun-if-changed=bin/");
        
        println!("Downloading required binaries...");
        let output = Command::new("node")
            .arg(script_path)
            .output();
            
        match output {
            Ok(result) => {
                if result.status.success() {
                    println!("Binary download completed successfully");
                    // Print stdout for visibility
                    if !result.stdout.is_empty() {
                        println!("{}", String::from_utf8_lossy(&result.stdout));
                    }
                } else {
                    println!("cargo:warning=Binary download failed with exit code: {}", 
                        result.status.code().unwrap_or(-1));
                    if !result.stderr.is_empty() {
                        println!("cargo:warning=Error: {}", String::from_utf8_lossy(&result.stderr));
                    }
                    // Don't fail the build if binary download fails
                    // Users can still provide their own binaries or use system ones
                    println!("cargo:warning=Continuing build without downloaded binaries. Users can still provide their own or use system-installed tools.");
                }
            }
            Err(e) => {
                println!("cargo:warning=Failed to execute binary download script: {}", e);
                println!("cargo:warning=Make sure Node.js is installed and available in PATH");
                println!("cargo:warning=Continuing build without downloaded binaries.");
            }
        }
    } else {
        println!("cargo:warning=Binary download script not found at: {:?}", script_path);
        println!("cargo:warning=Binaries will need to be provided manually or installed system-wide");
    }
}