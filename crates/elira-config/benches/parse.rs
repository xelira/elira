//! Cold config parsing benchmark: `cargo bench -p elira-config`.

use std::hint::black_box;
use std::time::Instant;

use elira_config::Config;

fn sample() -> String {
    let mut text = String::from(
        "listen = \"127.0.0.1:8080\"\n\n[limits]\nmax_headers = 64\nmax_header_bytes = 16384\n",
    );
    for index in 0..50 {
        text.push_str(&format!(
            "\n[[upstreams]]\nname = \"app{index}\"\nservers = [\"127.0.0.1:300{}\"]\n",
            index % 10
        ));
        text.push_str(&format!(
            "\n[[routes]]\nhost = \"host{index}.example\"\npath = \"/api\"\nupstream = \"app{index}\"\n"
        ));
    }
    text
}

fn main() {
    let text = sample();
    let iterations = 2_000u32;
    let started = Instant::now();
    for _ in 0..iterations {
        black_box(Config::parse(black_box(&text)).expect("sample parses"));
    }
    let elapsed = started.elapsed() / iterations;
    println!("config parse (50 routes): {} us/op", elapsed.as_micros());
}
