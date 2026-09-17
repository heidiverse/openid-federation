# OpenID Federation

`openid-federation` is a Rust library for working with [OpenID Federation](https://openid.net/specs/openid-federation-1_0.html) trust chains.
It can fetch entity configurations and subordinate statements, build and verify a trust chain, and resolve metadata with federation policies.

## Quick start

Add the crate to a Rust project:

```toml
[dependencies]
openid-federation = { git = "https://github.com/heidiverse/openid-federation" }
serde_json = "1"
```

Then load and verify an entity configuration:

```rust
use openid_federation::DefaultFederationRelation;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut federation =
        DefaultFederationRelation::new_from_url("https://issuer.example")?;

    federation.build_trust()?;
    federation
        .verify()
        .map_err(|errors| format!("trust-chain verification failed: {errors:?}"))?;

    let metadata = federation.resolve_metadata(None);
    println!("{}", serde_json::to_string_pretty(&metadata)?);
    Ok(())
}
```

For applications that already have JWTs, `FederationRelation::from_trust_chain` and `FederationRelation::from_trust_cache` allow trust evaluation without fetching the chain first. Async equivalents are available for network operations.

## Development

Run the formatter and tests from the repository root:

```sh
cargo fmt --all
cargo test
```

The `test-server` directory contains a small local server used by integration tests.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
