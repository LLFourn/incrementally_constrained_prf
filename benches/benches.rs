#![allow(non_upper_case_globals)]
use criterion::{criterion_group, criterion_main, Criterion};
use incrementally_constrained_prf::constrained_prf as cprf;
use lightning::ln::chan_utils::{build_commitment_secret, CounterpartyCommitmentSecrets};
const secret: [u8; 32] = [0xFFu8; 32];
const n: u64 = 1 << 0;

fn bench_prf<P: cprf::Prg32To64>(c: &mut Criterion, name: &str) {
    c.bench_function(&format!("{}_single_eval", name), |b| {
        b.iter(|| P::generate(&secret))
    });
    c.bench_function(&format!("{}_increment", name), |b| {
        let sk = cprf::SecretKey(secret);
        let prf = cprf::IncrementallyConstrainedPrf::<P>::default();
        let secrets = (0..n).map(|i| prf.evaluate(&sk, i)).collect::<Vec<_>>();
        b.iter(|| {
            let mut ck = cprf::ConstrainedKey::default();
            for i in 0..n {
                let next_secret = secrets[i as usize];
                prf.increment(&mut ck, i, next_secret).unwrap();
            }
        })
    });

    c.bench_function(&format!("{}_evaluate", name), |b| {
        let prf = cprf::IncrementallyConstrainedPrf::<cprf::ChaCha20>::default();
        let sk = cprf::SecretKey(secret);
        b.iter(|| {
            for i in 0..n {
                let _ = prf.evaluate(&sk, i);
            }
        });
    });
}

fn compare_ln_to_prf(c: &mut Criterion) {
    c.bench_function("ln_provide_secret", |b| {
        let end = 0xFFFFFFFFFFFF;
        let start = end - n;
        let secrets = (start..=end)
            .rev()
            .map(|i| build_commitment_secret(&secret, i))
            .collect::<Vec<[u8; 32]>>();
        b.iter(|| {
            let mut counter_party_secret = CounterpartyCommitmentSecrets::new();
            for i in 0..n {
                let tmp = secrets[i as usize];
                counter_party_secret.provide_secret(end - i, tmp).unwrap();
            }
        });
    });

    c.bench_function("ln_build_commitment_secret", |b| {
        let end = 0xFFFFFFFFFFFF;
        let start = end - n;
        b.iter(|| {
            for i in start..end {
                let _ = build_commitment_secret(&secret, i);
            }
        });
    });

    bench_prf::<cprf::ChaCha20>(c, "chacha");
    bench_prf::<cprf::Sha512>(c, "sha512");
}

criterion_group!(benches, compare_ln_to_prf);
criterion_main!(benches);
