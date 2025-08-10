mod legacy_wrappers; // after you copy tools/generated/legacy_wrappers.rs

#[tokio::main]
async fn main() {
  tauri::Builder::default()
    .invoke_handler(tauri::generate_handler![
      // paste content from tools/generated/REGISTER_CMDS.txt
    ])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}