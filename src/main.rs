mod core;

#[cfg(feature = "cli")]
mod cli;

#[cfg(feature = "gui")]
mod gui;

fn main() {
    env_logger::init();

    #[cfg(feature = "cli")]
    {
        use clap::Parser;
        let args = cli::Cli::parse();
        if let Err(e) = cli::run(args) {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }

    #[cfg(not(feature = "cli"))]
    {
        eprintln!("No mode selected. Build with --features cli or --features gui");
        std::process::exit(1);
    }
}
