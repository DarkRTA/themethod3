use clap::Parser;

#[derive(Parser)]
struct Args {
    infile: String,
    outfile: String,
}

fn main() {
    let args = Args::parse();

    let mut mogg_data = std::fs::read(args.infile).unwrap();
    toasters::decrypt_mogg(&mut mogg_data);
    std::fs::write(args.outfile, mogg_data).unwrap();
}
