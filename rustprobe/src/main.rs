// Uses smallvec and regex. hyper, tokio, rustc-serialize and chrono are
// declared in Cargo.toml but never used.
use smallvec::SmallVec;

fn main() {
    let mut values: SmallVec<[u8; 4]> = SmallVec::new();
    values.insert_many(0, std::env::args().map(|a| a.len() as u8));
    let pattern = std::env::args().nth(1).unwrap_or_default();
    let re = regex::Regex::new(&pattern).unwrap();
    println!("{:?} {}", values, re.is_match("x"));
}
