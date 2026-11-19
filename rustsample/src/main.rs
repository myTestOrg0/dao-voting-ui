use regex::Regex;

fn main() {
    let re = Regex::new(r"^\d+$").unwrap();
    println!("{} {}", re.is_match("42"), chrono::Utc::now());
}
