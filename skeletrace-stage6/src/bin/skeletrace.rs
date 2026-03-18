use skeletrace::{run_cli_command, CliCommand};

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let command = CliCommand::parse_from(std::env::args())?;
    let response = run_cli_command(command)?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}
