package org.twostack.tstokenlib4j.transaction;

import org.twostack.bitcoin4j.ECKey;
import org.twostack.bitcoin4j.PrivateKey;
import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.exception.SigHashException;
import org.twostack.bitcoin4j.exception.SignatureDecodeException;
import org.twostack.bitcoin4j.exception.TransactionException;
import org.twostack.bitcoin4j.transaction.SigHashType;
import org.twostack.bitcoin4j.transaction.Transaction;
import org.twostack.bitcoin4j.transaction.TransactionOutput;
import org.twostack.bitcoin4j.transaction.TransactionSigner;

import java.io.IOException;

/**
 * Adapts a {@link SigningCallback} into a bitcoin4j {@link TransactionSigner}.
 *
 * <p>Creates a proxy {@link PrivateKey} that delegates {@code sign()} to the
 * callback while preserving the correct public key (needed for P2PKH-style
 * unlock scripts). The underlying {@code TransactionBuilder} workflow is
 * completely unchanged — it receives a standard {@code TransactionSigner}
 * and never knows the private key isn't local.
 */
public final class SignerAdapter {

    private SignerAdapter() {}

    /**
     * Creates a {@link TransactionSigner} backed by the given signing callback.
     *
     * @param callback  signs sighash digests externally (KMS, HSM, remote wallet)
     * @param publicKey the public key corresponding to the signing key — used in
     *                  unlock scripts but never for signing
     * @return a TransactionSigner usable with {@code TransactionBuilder}
     */
    public static TransactionSigner fromCallback(SigningCallback callback, PublicKey publicKey) {
        int sigHashType = SigHashType.FORKID.value | SigHashType.ALL.value;
        return fromCallback(callback, publicKey, sigHashType);
    }

    /**
     * Creates a {@link TransactionSigner} backed by the given signing callback
     * with a custom sighash type.
     *
     * @param callback    signs sighash digests externally
     * @param publicKey   the public key corresponding to the signing key
     * @param sigHashType the sighash flags (e.g. FORKID | ALL)
     * @return a TransactionSigner usable with {@code TransactionBuilder}
     */
    public static TransactionSigner fromCallback(SigningCallback callback, PublicKey publicKey, int sigHashType) {
        CallbackPrivateKey proxyKey = new CallbackPrivateKey(callback, publicKey);
        return new InputIndexAwareTransactionSigner(sigHashType, proxyKey);
    }

    /**
     * A PrivateKey subclass that delegates {@code sign()} to a
     * {@link SigningCallback} while carrying the correct public key.
     *
     * <p>The ECKey passed to the super constructor is public-key-only
     * (no private key material). Only {@code sign()} is overridden;
     * {@code getPublicKey()} works normally via the ECKey.
     *
     * <p>The {@code currentInputIndex} is set by the TransactionSigner
     * before each sign call via the {@link #setCurrentInputIndex} method,
     * allowing the signing callback to derive the correct key per input.
     */
    static final class CallbackPrivateKey extends PrivateKey {

        private final SigningCallback callback;
        private int currentInputIndex;
        private byte[] currentScriptPubKey;

        CallbackPrivateKey(SigningCallback callback, PublicKey publicKey) {
            super(ECKey.fromPublicOnly(publicKey.getPubKeyBytes()));
            this.callback = callback;
        }

        void setCurrentInput(int inputIndex, byte[] scriptPubKey) {
            this.currentInputIndex = inputIndex;
            this.currentScriptPubKey = scriptPubKey;
        }

        @Override
        public byte[] sign(byte[] buffer) {
            return callback.sign(buffer, currentInputIndex, currentScriptPubKey);
        }
    }

    /**
     * TransactionSigner that passes the locking script of the output being spent
     * to the CallbackPrivateKey before each sign call, so the signing callback
     * can resolve the owner address and derive the correct key.
     */
    private static final class InputIndexAwareTransactionSigner extends TransactionSigner {

        private final CallbackPrivateKey callbackKey;

        InputIndexAwareTransactionSigner(int sigHashType, CallbackPrivateKey callbackKey) {
            super(sigHashType, callbackKey);
            this.callbackKey = callbackKey;
        }

        @Override
        public Transaction sign(Transaction unsignedTxn, TransactionOutput utxo, int inputIndex)
                throws TransactionException, IOException, SigHashException, SignatureDecodeException {
            callbackKey.setCurrentInput(inputIndex, utxo.getScript().getProgram());
            return super.sign(unsignedTxn, utxo, inputIndex);
        }
    }
}
