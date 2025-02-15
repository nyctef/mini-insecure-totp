use base32::Alphabet::Rfc4648;
use clap::Parser;
use color_eyre::{eyre::eyre, Result};
use hmac::{digest::InvalidLength, Hmac, Mac};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

fn decode_secret(secret: &str) -> Result<Vec<u8>> {
    base32::decode(Rfc4648 { padding: true }, secret)
        .ok_or_else(|| eyre!("failed to understand secret \"{secret}\" (is it RFC4648 base32?)"))
}

fn generate_totp(timestamp: u64, time_step: u64, secret: &[u8]) -> Result<String> {
    let time_counter = timestamp / time_step;
    let time_bytes = time_counter.to_be_bytes();

    // https://en.wikipedia.org/wiki/Time-based_one-time_password
    // https://en.wikipedia.org/wiki/HMAC-based_one-time_password
    // https://datatracker.ietf.org/doc/html/rfc6238
    // https://datatracker.ietf.org/doc/html/rfc4226
    //
    // TOTP = HOTP(key, time_counter)
    // HOTP(K,C) = Truncate(HMAC-SHA-1(K,C))

    let mut mac = Hmac::<Sha1>::new_from_slice(secret)
        .map_err(|_: InvalidLength| eyre!("Secret had invalid length"))?;
    mac.update(&time_bytes);
    let result = mac.finalize().into_bytes();

    // Generate 6-digit code: first extract 4 bytes from our 20-byte HMAC

    // The offset is the low-order 4 bits of the last byte of the HMAC
    // This means we randomly pick which four bytes to extract from the HMAC
    // A four bit value ranges from 0..15, so the selected bytes can be
    // between [0,4) and [15,19).
    let offset = (result[result.len() - 1] & 0xf) as usize;

    // note the spec masks with 0x7f for the most-significant byte.
    // this means the highest bit isn't set in the resulting number,
    // which prevents it from being interpreted as negative.
    //
    // This means we don't get any confusion between the exact definition
    // of modulo vs remainder functions for negative numbers.
    let code = ((u32::from(result[offset]) & 0x7f) << 24)
        | (u32::from(result[offset + 1]) << 16)
        | (u32::from(result[offset + 2]) << 8)
        | u32::from(result[offset + 3]);
    // then take the u32 we assembled from our four bytes mod 10^6:
    Ok(format!(
        "{:03} {:03}",
        (code % 1_000_000) / 1000,
        code % 1000
    ))
}

#[derive(clap::Parser)]
struct Cli {
    secret: String,
}

fn main() {
    color_eyre::install().unwrap();

    let cli = Cli::parse();

    let secret = decode_secret(&cli.secret).unwrap();
    let time_step = 30; // Standard TOTP time step
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let code = generate_totp(timestamp, time_step, &secret).unwrap();
    println!("{}", code);
}
