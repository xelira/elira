//! Microbenchmark with no framework: `cargo bench -p elira-cache`.

use std::hint::black_box;
use std::time::Instant;

use elira_cache::Cache;
use http::{HeaderMap, HeaderValue};

fn main() {
    let cache = Cache::new(64 * 1024 * 1024, std::time::Duration::from_secs(60));
    let request = HeaderMap::new();
    let mut response = HeaderMap::new();
    response.insert("cache-control", HeaderValue::from_static("max-age=60"));
    let body = vec![0u8; 512];
    let now = Instant::now();

    cache.insert("example.com/", &request, &response, 200, body.clone(), now);

    let iterations = 200_000u32;
    let started = Instant::now();
    for _ in 0..iterations {
        black_box(cache.get(black_box("example.com/"), &request, Instant::now()));
    }
    let hit = started.elapsed() / iterations;
    println!("cache hit: {} ns/op", hit.as_nanos());

    let started = Instant::now();
    for index in 0..20_000u32 {
        let key = format!("example.com/{index}");
        cache.insert(&key, &request, &response, 200, body.clone(), Instant::now());
    }
    let insert = started.elapsed() / 20_000;
    println!("cache insert: {} ns/op", insert.as_nanos());
}
