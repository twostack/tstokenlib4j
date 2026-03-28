package org.twostack.tstokenlib4j.transaction;

import org.junit.BeforeClass;
import org.junit.Test;
import org.twostack.bitcoin4j.*;
import org.twostack.bitcoin4j.crypto.ChildNumber;
import org.twostack.bitcoin4j.crypto.DeterministicKey;
import org.twostack.bitcoin4j.crypto.HDKeyDerivation;
import org.twostack.bitcoin4j.params.NetworkAddressType;
import org.twostack.bitcoin4j.script.Interpreter;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptBuilder;
import org.twostack.bitcoin4j.transaction.*;
import org.twostack.tstokenlib4j.lock.ModP2PKHLockBuilder;
import org.twostack.tstokenlib4j.parser.PP1TemplateRegistrar;
import org.twostack.tstokenlib4j.unlock.ModP2PKHUnlockBuilder;

import java.math.BigInteger;
import java.util.*;

import static org.junit.Assert.*;

/**
 * Verifies that InputIndexAwareTransactionSigner correctly passes the
 * locking script through the signing chain and produces valid signatures
 * for each input independently — including multi-key HD derivation.
 */
public class SignerAdapterTest {

    private static final EnumSet<Script.VerifyFlag> VERIFY_FLAGS = EnumSet.of(
            Script.VerifyFlag.SIGHASH_FORKID,
            Script.VerifyFlag.UTXO_AFTER_GENESIS);

    private static DeterministicKey masterKey;

    @BeforeClass
    public static void setup() {
        PP1TemplateRegistrar.registerAll();
        // Deterministic seed for reproducible tests
        byte[] seed = Sha256Hash.hash("test-seed-for-signer-adapter".getBytes());
        masterKey = HDKeyDerivation.createMasterPrivateKey(seed);
    }

    /**
     * Derive child key at m/44'/1'/0'/0/{index} — same path as CryptoService.derivePrivateKey
     */
    private static DeterministicKey deriveChild(int index) {
        DeterministicKey purpose = HDKeyDerivation.deriveChildKey(masterKey, new ChildNumber(44, true));
        DeterministicKey coin = HDKeyDerivation.deriveChildKey(purpose, new ChildNumber(1, true));
        DeterministicKey acct = HDKeyDerivation.deriveChildKey(coin, new ChildNumber(0, true));
        DeterministicKey change = HDKeyDerivation.deriveChildKey(acct, new ChildNumber(0, false));
        return HDKeyDerivation.deriveChildKey(change, new ChildNumber(index, false));
    }

    private static ECKey ecKeyAt(int index) {
        return ECKey.fromPrivate(deriveChild(index).getPrivKeyBytes(), true);
    }

    private static PublicKey pubKeyAt(int index) {
        return PublicKey.fromBytes(ecKeyAt(index).getPubKey());
    }

    private static String addressAt(int index) {
        return org.twostack.bitcoin4j.address.LegacyAddress.fromPubKeyHash(
                NetworkAddressType.TEST_PKH, pubKeyAt(index).getPubKeyHash()).toBase58();
    }

    @Test
    public void scriptPubKeyBytes_flowThroughToCallback() throws Exception {
        ECKey key0 = ecKeyAt(0);
        PublicKey pub0 = pubKeyAt(0);

        List<byte[]> receivedScripts = new ArrayList<>();

        SigningCallback callback = new SigningCallback() {
            @Override public byte[] sign(byte[] sighash) { return signWith(key0, sighash); }
            @Override public byte[] sign(byte[] sighash, int inputIndex, byte[] scriptPubKey) {
                receivedScripts.add(scriptPubKey);
                return signWith(key0, sighash);
            }
        };

        Script p2pkh = ScriptBuilder.createP2PKHOutputScript(pub0.getPubKeyHash());
        Script modP2pkh = new ModP2PKHLockBuilder(pub0.getPubKeyHash()).getLockingScript();
        Transaction parentA = makeSingleOutputTx(p2pkh, 50000);
        Transaction parentB = makeSingleOutputTx(modP2pkh, 30000);

        int sigHashAll = SigHashType.FORKID.value | SigHashType.ALL.value;
        TransactionSigner signer = SignerAdapter.fromCallback(callback, pub0, sigHashAll);

        new TransactionBuilder()
                .spendFromTransaction(signer, parentA, 0, TransactionInput.MAX_SEQ_NUMBER, new P2PKHUnlockBuilder(pub0))
                .spendFromTransaction(signer, parentB, 0, TransactionInput.MAX_SEQ_NUMBER, new ModP2PKHUnlockBuilder(pub0))
                .spendTo(new P2PKHLockBuilder(org.twostack.bitcoin4j.address.LegacyAddress.fromPubKeyHash(
                        NetworkAddressType.TEST_PKH, pub0.getPubKeyHash())), BigInteger.valueOf(5000))
                .build(false);

        assertEquals(2, receivedScripts.size());
        assertArrayEquals(p2pkh.getProgram(), receivedScripts.get(0));
        assertArrayEquals(modP2pkh.getProgram(), receivedScripts.get(1));
    }

    /**
     * Two inputs locked to different HD-derived keys (index 0 and index 1).
     * The callback uses the scriptPubKey to determine which child key to sign with.
     * Both inputs must pass the script interpreter.
     */
    @Test
    public void multiKey_hdDerived_signsEachInputWithCorrectKey() throws Exception {
        PublicKey pub0 = pubKeyAt(0);
        PublicKey pub1 = pubKeyAt(1);

        // P2PKH locked to key at index 0
        Script p2pkh0 = ScriptBuilder.createP2PKHOutputScript(pub0.getPubKeyHash());
        // ModP2PKH locked to key at index 1
        Script modP2pkh1 = new ModP2PKHLockBuilder(pub1.getPubKeyHash()).getLockingScript();

        Transaction parentA = makeSingleOutputTx(p2pkh0, 50000);
        Transaction parentB = makeSingleOutputTx(modP2pkh1, 30000);

        // Address → derivation index mapping (same as signing actor would have)
        Map<String, Integer> addressToIndex = new HashMap<>();
        addressToIndex.put(addressAt(0), 0);
        addressToIndex.put(addressAt(1), 1);

        // Callback mimics the signing actor: resolves address from script, derives key
        SigningCallback callback = new SigningCallback() {
            @Override
            public byte[] sign(byte[] sighash) {
                return signWith(ecKeyAt(0), sighash); // fallback
            }

            @Override
            public byte[] sign(byte[] sighash, int inputIndex, byte[] scriptPubKey) {
                String address = extractAddress(scriptPubKey);
                int derivIdx = addressToIndex.getOrDefault(address, 0);
                return signWith(ecKeyAt(derivIdx), sighash);
            }
        };

        int sigHashAll = SigHashType.FORKID.value | SigHashType.ALL.value;
        TransactionSigner signerA = SignerAdapter.fromCallback(callback, pub0, sigHashAll);
        TransactionSigner signerB = SignerAdapter.fromCallback(callback, pub1, sigHashAll);

        Transaction tx = new TransactionBuilder()
                .spendFromTransaction(signerA, parentA, 0, TransactionInput.MAX_SEQ_NUMBER, new P2PKHUnlockBuilder(pub0))
                .spendFromTransaction(signerB, parentB, 0, TransactionInput.MAX_SEQ_NUMBER, new ModP2PKHUnlockBuilder(pub1))
                .spendTo(new P2PKHLockBuilder(org.twostack.bitcoin4j.address.LegacyAddress.fromPubKeyHash(
                        NetworkAddressType.TEST_PKH, pub0.getPubKeyHash())), BigInteger.valueOf(5000))
                .build(false);

        // Both inputs pass the script interpreter
        verifySpend(tx, 0, parentA, 0);
        verifySpend(tx, 1, parentB, 0);
    }

    /**
     * Verify that using the wrong key for an input FAILS the interpreter —
     * confirms the test is meaningful.
     */
    @Test
    public void wrongKey_failsInterpreter() throws Exception {
        PublicKey pub0 = pubKeyAt(0);
        PublicKey pub1 = pubKeyAt(1);

        // ModP2PKH locked to key at index 1
        Script modP2pkh1 = new ModP2PKHLockBuilder(pub1.getPubKeyHash()).getLockingScript();
        Transaction parentTx = makeSingleOutputTx(modP2pkh1, 50000);

        // Sign with key 0 instead of key 1
        SigningCallback wrongCallback = sighash -> signWith(ecKeyAt(0), sighash);
        int sigHashAll = SigHashType.FORKID.value | SigHashType.ALL.value;
        TransactionSigner signer = SignerAdapter.fromCallback(wrongCallback, pub0, sigHashAll);

        Transaction tx = new TransactionBuilder()
                .spendFromTransaction(signer, parentTx, 0, TransactionInput.MAX_SEQ_NUMBER, new ModP2PKHUnlockBuilder(pub0))
                .spendTo(new P2PKHLockBuilder(org.twostack.bitcoin4j.address.LegacyAddress.fromPubKeyHash(
                        NetworkAddressType.TEST_PKH, pub0.getPubKeyHash())), BigInteger.valueOf(5000))
                .build(false);

        try {
            verifySpend(tx, 0, parentTx, 0);
            fail("Expected interpreter to fail with wrong key");
        } catch (Exception expected) {
            // Expected — wrong key should fail EQUALVERIFY or CHECKSIG
        }
    }

    // ── Helpers ──

    private static Transaction makeSingleOutputTx(Script lockingScript, long sats) {
        Transaction tx = new Transaction();
        tx.addInput(new TransactionInput(new byte[32], 0xFFFFFFFFL, 0xFFFFFFFFL, new DefaultUnlockBuilder()));
        tx.addOutput(new TransactionOutput(BigInteger.valueOf(sats), lockingScript));
        return tx;
    }

    private void verifySpend(Transaction spendingTx, int inputIndex,
                             Transaction parentTx, int parentVout) {
        Script scriptSig = spendingTx.getInputs().get(inputIndex).getScriptSig();
        Script scriptPubKey = parentTx.getOutputs().get(parentVout).getScript();
        long sats = parentTx.getOutputs().get(parentVout).getAmount().longValue();
        new Interpreter().correctlySpends(
                scriptSig, scriptPubKey, spendingTx, inputIndex,
                VERIFY_FLAGS, Coin.valueOf(sats));
    }

    private static byte[] signWith(ECKey key, byte[] sighash) {
        ECKey.ECDSASignature sig = key.sign(Sha256Hash.wrap(sighash));
        return sig.encodeToDER();
    }

    /**
     * Extract address from P2PKH or ModP2PKH script bytes.
     * This mimics what the plugin resolver does in production.
     */
    private static String extractAddress(byte[] script) {
        // P2PKH: 76 a9 14 <20B> 88 ac
        if (script.length == 25 && script[0] == 0x76 && script[1] == (byte) 0xa9 && script[2] == 0x14) {
            byte[] pkh = new byte[20];
            System.arraycopy(script, 3, pkh, 0, 20);
            return org.twostack.bitcoin4j.address.LegacyAddress.fromPubKeyHash(NetworkAddressType.TEST_PKH, pkh).toBase58();
        }
        // ModP2PKH: 7c 76 a9 14 <20B> 88 ac
        if (script.length == 26 && script[0] == 0x7c && script[1] == 0x76 && script[2] == (byte) 0xa9 && script[3] == 0x14) {
            byte[] pkh = new byte[20];
            System.arraycopy(script, 4, pkh, 0, 20);
            return org.twostack.bitcoin4j.address.LegacyAddress.fromPubKeyHash(NetworkAddressType.TEST_PKH, pkh).toBase58();
        }
        return null;
    }
}
