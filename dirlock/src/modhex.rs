/*
 * Copyright © 2026 Valve Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/// A simple implementation of the modhex encoding. This is base16
/// with an alternate alphabet (`MODEX_CHARS`).

use anyhow::{anyhow, bail, Result};

const MODHEX_CHARS: &[u8; 16] = b"cbdefghijklnrtuv";
const GROUP_BYTES: usize = 4; // Add a dash every 4 bytes (8 characters)

/// Returns an arbitrary binary array as a modhex-encoded String
pub fn encode(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "".into();
    }

    let ndashes = (bytes.len() - 1) / GROUP_BYTES;
    let mut output = String::with_capacity(bytes.len() * 2 + ndashes);

    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 && i % GROUP_BYTES == 0 {
            output.push('-');
        }

        let high = (b >> 4) as usize;
        let low = (b & 0x0F) as usize;
        output.push(MODHEX_CHARS[high] as char);
        output.push(MODHEX_CHARS[low] as char);
    }

    output
}

/// Decodes a modex-encoded string (passed as a slice of ASCII bytes).
/// The output buffer must have the exact size to fit the decoded data
/// (that is, half of the length of the string, after removing any dashes).
pub fn decode_ascii_bytes_into(input: &[u8], output: &mut [u8]) -> Result<()> {
    const ERR_LONG: &str = "Modhex input too short";
    const ERR_SHORT: &str = "Modhex input too short";
    const ERR_INVALID: &str = "Invalid modhex input";

    // Return early if we already know that the input is too short
    if input.len() < output.len() * 2 {
        bail!(ERR_SHORT);
    }

    let mut input_chars = input.iter()
        .filter(|&&c| c != b'-')
        .map(|c| c.to_ascii_lowercase());

    for val in output.iter_mut() {
        let high_char = input_chars.next().ok_or_else(|| anyhow!(ERR_SHORT))?;
        let low_char = input_chars.next().ok_or_else(|| anyhow!(ERR_SHORT))?;

        let high = MODHEX_CHARS.iter().position(|&c| c == high_char)
            .ok_or_else(|| anyhow!(ERR_INVALID))?;
        let low = MODHEX_CHARS.iter().position(|&c| c == low_char)
            .ok_or_else(|| anyhow!(ERR_INVALID))?;

        *val = ((high << 4) | low) as u8;
    }

    if input_chars.next().is_some() {
        bail!(ERR_LONG);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use super::{encode, decode_ascii_bytes_into};

    /// Each entry: [input (modhex), expected decoded value (hex), expected re-encoded value (modhex)]
    const MODHEX_DATA: &[[&str; 3]] = &[
        [
            "cccccccc-CCCCCCCC-cccccccc-CCCCCCCC-cccccccc-cCcCcCcC-cccccccc-CcCcCcCc",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-cccccccc",
        ],
        [
            "vvvv-vvvv-vvvv-vvvv-vvvv-vvvv-vvvv-vvvv-vvvv-vvvv-vvvv-vvvv-vvvv-vvvv-vvvv-vvvv",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "vvvvvvvv-vvvvvvvv-vvvvvvvv-vvvvvvvv-vvvvvvvv-vvvvvvvv-vvvvvvvv-vvvvvvvv",
        ],
        [
            "cbdefghijklnrtuvcbdefghijklnrtuvVUTRNLKJIHGFEDBCVUTRNLKJIHGFEDBC",
            "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210",
            "cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-vutrnlkj-ihgfedbc-vutrnlkj-ihgfedbc",
        ],
        [
            "--fc---gnutnkndj-feJNH-kkc--bcnkjhcgv--rijn-KCVKUNVE-cfc-Ltlng-tultKUHI-lcjiLHRJ--",
            "405bedb9b28438b699010b98605fc78b90f9ebf3040adab5dead9e67a087a6c8",
            "fcgnutnk-ndjfejnh-kkcbcnkj-hcgvrijn-kcvkunve-cfcltlng-tultkuhi-lcjilhrj",
        ],
    ];

    #[test]
    fn test_modhex_valid() -> Result<()> {
        for item in MODHEX_DATA {
            let modhex_input = item[0];
            let expected_decoded = hex::decode(item[1]).unwrap();
            let expected_encoded = item[2];

            // Decode
            let mut output = [0u8; 32];
            decode_ascii_bytes_into(modhex_input.as_bytes(), &mut output)?;
            assert_eq!(output, expected_decoded.as_ref());

            // Encode
            let encoded = encode(&output);
            assert_eq!(encoded, expected_encoded);
        }

        Ok(())
    }

    /// Invalid modhex inputs: too short, too long, invalid characters
    const INVALID_MODHEX_DATA: &[&str] = &[
        "cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-cccccc",
        "cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-ccccccc",
        "cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-ccccccccc",
        "cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-cccccccccc",
        "cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-cccccccz",
        "cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-cccccccc-cccccc@#",
    ];

    #[test]
    fn test_modhex_invalid() -> Result<()> {
        for input in INVALID_MODHEX_DATA {
            let mut output = [0u8; 32];
            let result = decode_ascii_bytes_into(input.as_bytes(), &mut output);
            assert!(result.is_err(), "Unexpected success decoding modhex value {input}");
        }
        Ok(())
    }
}
