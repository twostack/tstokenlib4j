package org.twostack.tstokenlib4j.transaction;

/**
 * Functional interface for external signing of transaction sighashes.
 *
 * <p>Decouples transaction construction from private key management.
 * The caller provides a callback that signs a sighash digest without
 * exposing the private key to the transaction-building code.
 *
 * <p>This interface has the same shape as libspiffy4j's
 * {@code CallbackTransactionSigner}, allowing direct lambda passing
 * between the two systems without any dependency.
 *
 * <p>Usage:
 * <pre>{@code
 * // With a local key:
 * SigningCallback signer = sighash -> privateKey.sign(sighash);
 *
 * // With a KMS:
 * SigningCallback signer = sighash -> kms.sign(merchantId, sighash);
 *
 * // With libspiffy4j's CallbackTransactionSigner:
 * CallbackTransactionSigner spiffySigner = ...;
 * SigningCallback signer = sighash -> spiffySigner.sign(sighash, 0);
 * }</pre>
 */
@FunctionalInterface
public interface SigningCallback {

    /**
     * Signs a sighash digest and returns a DER-encoded ECDSA signature.
     *
     * @param sighash the double-SHA256 hash of the sighash preimage (32 bytes)
     * @return DER-encoded signature bytes
     */
    byte[] sign(byte[] sighash);
}
