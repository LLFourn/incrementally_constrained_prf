use incrementally_constrained_prf::{ChaCha20, IncrementallyConstrainedPrf, SecretKey, Sha512};
use std::env;

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let n = args
        .get(2)
        .unwrap_or(&"1000".to_string())
        .parse::<u64>()
        .unwrap();
    let key = SecretKey([42u8; 32]);
    let mut thing = 0u8;
    match args.get(1).map(String::as_str) {
        Some("sha512") => {
            let prf = IncrementallyConstrainedPrf::<Sha512>::default();
            for i in 0..n {
                thing ^= prf.evaluate(&key, i)[0];
            }
        }
        Some("chacha20") => {
            let prf = IncrementallyConstrainedPrf::<ChaCha20>::default();
            for i in 0..n {
                thing ^= prf.evaluate(&key, i)[0];
            }
        }
        _ => panic!("first argument should be sha512/chacha20"),
    }

    println!("{}", thing);
}
