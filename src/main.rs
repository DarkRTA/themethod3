use clap::Parser;

#[derive(Parser)]
struct Args {
    infile: String,
    outfile: String,
}

fn main() {
    env_logger::Builder::new()
        .format_timestamp(None)
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let args = Args::parse();
    let mogg_data = std::fs::read(args.infile).unwrap();
    let mogg_data = themethod3::decrypt_mogg(&mogg_data).unwrap();
    std::fs::write(args.outfile, mogg_data).unwrap();
}
