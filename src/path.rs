// Path syntax adapted from https://github.com/ZcashFoundation/frost/pull/1083
// at 6f55efc80e316980591e51ec66792780d0aea2f5 (MIT OR Apache-2.0).

use alloc::vec::Vec;
use core::{fmt, str::FromStr};

use crate::Error;

const PATH_ROOT: &str = "m";
const PATH_SEPARATOR: char = '/';
const HARDENED_SUFFIX: char = '\'';
const DECIMAL_ZERO: char = '0';

/// Maximum number of segments in a derivation path.
pub const MAX_PATH_DEPTH: usize = 64;

/// A validated non-hardened derivation path `m/<i0>/<i1>/...` with 1 to
/// [`MAX_PATH_DEPTH`] full-range `u32` indices.
///
/// The empty path `m` is rejected so callers never use the root key as a child.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivationPath {
    indices: Vec<u32>,
}

impl DerivationPath {
    /// Builds a path from non-hardened indices.
    pub fn new(indices: &[u32]) -> Result<Self, Error> {
        if indices.is_empty() {
            return Err(Error::EmptyPath);
        }
        if indices.len() > MAX_PATH_DEPTH {
            return Err(Error::PathTooDeep);
        }
        Ok(Self {
            indices: indices.to_vec(),
        })
    }

    /// The path indices, root first.
    pub fn indices(&self) -> &[u32] {
        &self.indices
    }
}

impl FromStr for DerivationPath {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut segments = input.split(PATH_SEPARATOR);
        if segments.next() != Some(PATH_ROOT) {
            return Err(Error::NonCanonicalPath);
        }
        let indices = segments.map(parse_index).collect::<Result<Vec<_>, _>>()?;
        Self::new(&indices)
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(PATH_ROOT)?;
        for index in &self.indices {
            write!(formatter, "{PATH_SEPARATOR}{index}")?;
        }
        Ok(())
    }
}

fn parse_index(token: &str) -> Result<u32, Error> {
    if token.ends_with(HARDENED_SUFFIX) {
        return Err(Error::HardenedDerivationUnsupported);
    }
    if token.is_empty()
        || (token.len() > 1 && token.starts_with(DECIMAL_ZERO))
        || !token.as_bytes().iter().all(u8::is_ascii_digit)
    {
        return Err(Error::NonCanonicalPath);
    }
    token.parse().map_err(|_| Error::PathIndexOverflow)
}
