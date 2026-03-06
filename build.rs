use std::path::Path;

fn main() {
    // Convert icon.png to icon.ico for Windows PE embedding
    let ico_path = Path::new("icon.ico");
    if !ico_path.exists() {
        let png_data = std::fs::read("icon.png").expect("Failed to read icon.png");
        let img = image::load_from_memory(&png_data).expect("Failed to decode icon.png");

        // Resize to standard icon sizes and save as ICO
        let img = img.resize_exact(256, 256, image::imageops::FilterType::Lanczos3);
        img.save("icon.ico").expect("Failed to save icon.ico");
    }

    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        res.set_icon("icon.ico");
        if let Err(e) = res.compile() {
            eprintln!("Warning: Failed to set Windows icon: {}", e);
        }
    }
}
