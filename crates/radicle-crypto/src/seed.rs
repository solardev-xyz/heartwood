use zeroize::Zeroizing;

#[derive(Clone)]
pub struct Seed(Zeroizing<[u8; Self::BYTES]>);

/// Redacted: a formatted seed would outlive the seed's wipe, in a log or an
/// error report.
impl core::fmt::Debug for Seed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Seed(<redacted>)")
    }
}

impl Seed {
    pub const BYTES: usize = 32;

    pub fn new(seed: [u8; Self::BYTES]) -> Self {
        Seed(Zeroizing::from(seed))
    }

    #[cfg(any(test, all(feature = "test", feature = "alloc")))]
    pub fn mock(bytes: usize) -> Self {
        use alloc::vec::Vec;

        let bytes = core::iter::repeat_n(bytes, Self::BYTES / core::mem::size_of::<usize>())
            .flat_map(|bytes| bytes.to_be_bytes())
            .collect::<Vec<_>>();

        Self::new(bytes.try_into().expect("length matches"))
    }
}

impl AsRef<[u8; Self::BYTES]> for Seed {
    fn as_ref(&self) -> &[u8; Self::BYTES] {
        &self.0
    }
}

#[cfg(feature = "qcheck")]
impl qcheck::Arbitrary for Seed {
    fn arbitrary(g: &mut qcheck::Gen) -> Self {
        Self::new(qcheck::Arbitrary::arbitrary(g))
    }
}

#[cfg(test)]
mod test {
    use alloc::format;

    use super::*;

    #[test]
    // Review of heartwood #15, round 1: a formatted seed holds none of its
    // bytes, in decimal or in hex.
    fn a_formatted_seed_holds_none_of_its_bytes() {
        let bytes: [u8; Seed::BYTES] = core::array::from_fn(|i| i as u8 + 1);
        let seed = Seed::new(bytes);
        for formatted in [
            format!("{seed:?}"),
            format!("{seed:#?}"),
            format!("{seed:x?}"),
            format!("{:?}", Some(seed.clone())),
        ] {
            for byte in bytes {
                assert!(!formatted.contains(&format!("{byte}")), "{formatted}");
                assert!(!formatted.contains(&format!("{byte:02x}")), "{formatted}");
            }
        }
    }
}
