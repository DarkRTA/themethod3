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

    let mut mogg_data = std::fs::read(args.infile).unwrap();
    themethod3::decrypt_mogg(&mut mogg_data);
    std::fs::write(args.outfile, mogg_data).unwrap();
}
