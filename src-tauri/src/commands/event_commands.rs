use crate::scanning::events::EventStreamer;
use std::sync::Arc;
use tauri::{State, Window, Emitter};

#[tauri::command]
pub async fn setup_event_stream(
    window: Window,
    streamer: State<'_, Arc<EventStreamer>>,
) -> Result<(), String> {
    let mut rx = streamer.subscribe();
    
    tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            if let Err(e) = window.emit("scan-event", &event) {
                eprintln!("Failed to emit event: {}", e);
                break;
            }
        }
    });
    
    Ok(())
}