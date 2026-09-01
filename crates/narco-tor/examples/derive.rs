//! Show what a room code derives to, without touching the network.
//!
//!     cargo run -p narco-tor --example derive -- "YOUR-CODE-HERE"
//!
//! Run it on two machines with the same code and compare: the addresses match.
//! That is the whole reason Narco needs no server.

fn main() {
    let code = std::env::args().nth(1).unwrap_or_else(|| {
        let c = narco_proto::generate();
        println!("(no code given, generated one)\n");
        c
    });

    let derived = match narco_proto::kdf::derive(&code) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("rejected: {e}");
            std::process::exit(1);
        }
    };
    let (a, b) = narco_tor::identities(&derived);

    println!("code       {code}");
    println!("room id    {}", derived.room_id);
    println!("onion A    {}", a.address);
    println!("onion B    {}", b.address);
    println!(
        "\nBoth peers derive these from the code alone.\n\
         One publishes A and dials B; the other does the reverse.\n\
         Nothing was sent anywhere to compute this."
    );
}
