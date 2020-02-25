use crate::{PublicKey, Signature, SignatureError};

/// Verify a batch of `signatures` on `messages` with their respective `public_keys`.
///
/// # Inputs
///
/// * `messages` is a slice of byte slices, one per signed message.
/// * `signatures` is a slice of `Signature`s.
/// * `public_keys` is a slice of `PublicKey`s.
/// * `csprng` is an implementation of `Rng + CryptoRng`.
///
/// # Returns
///
/// * A `Result` whose `Ok` value is an emtpy tuple and whose `Err` value is a
///   `SignatureError` containing a description of the internal error which
///   occured.
///
/// # Examples
///
/// ```
/// extern crate ed25519_dalek;
/// extern crate rand;
///
/// use ed25519_dalek::verify_batch;
/// use ed25519_dalek::Keypair;
/// use ed25519_dalek::PublicKey;
/// use ed25519_dalek::Signature;
/// use rand::rngs::OsRng;
///
/// # fn main() {
/// let mut csprng = OsRng{};
/// let keypairs: Vec<Keypair> = (0..64).map(|_| Keypair::generate(&mut csprng)).collect();
/// let msg: &[u8] = b"They're good dogs Brant";
/// let messages: Vec<&[u8]> = (0..64).map(|_| msg).collect();
/// let signatures:  Vec<Signature> = keypairs.iter().map(|key| key.sign(&msg)).collect();
/// let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();
///
/// let result = verify_batch(&messages[..], &signatures[..], &public_keys[..]);
/// assert!(result.is_ok());
/// # }
/// ```
#[cfg(all(
	any(feature = "batch", feature = "batch_deterministic"),
	any(feature = "std", feature = "alloc")
))]
#[inline]
pub fn verify_batch(
	messages: &[&[u8]],
	signatures: &[Signature],
	public_keys: &[PublicKey],
) -> Result<(), SignatureError> {
	eddsa_dalek::verify_batch(messages, signatures, public_keys)
}
