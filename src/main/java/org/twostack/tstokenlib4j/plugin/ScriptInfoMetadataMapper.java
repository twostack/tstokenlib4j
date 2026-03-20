package org.twostack.tstokenlib4j.plugin;

import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.address.LegacyAddress;
import org.twostack.bitcoin4j.params.NetworkAddressType;
import org.twostack.bitcoin4j.script.ScriptInfo;
import org.twostack.tstokenlib4j.parser.*;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Converts a {@link ScriptInfo} subclass into a {@code Map<String, Object>}
 * suitable for libspiffy4j's {@code ScriptPlugin.extractMetadata()} return value.
 *
 * <p>All {@code byte[]} fields are hex-encoded. The {@code ownerPKH} is also
 * converted to a base58 address via the configured {@link NetworkAddressType},
 * stored under the {@code "ownerAddress"} key — required by the wallet's
 * {@code autoRecordOutputUtxos()} for ownership matching.
 */
final class ScriptInfoMetadataMapper {

    private ScriptInfoMetadataMapper() {}

    static Map<String, Object> toMetadata(ScriptInfo info, NetworkAddressType networkAddressType) {
        Map<String, Object> m = new LinkedHashMap<>();

        switch (info) {
            case PP1NftScriptInfo nft -> {
                putCommon(m, nft.getOwnerPKH(), nft.getTokenId(), "pp1_nft", networkAddressType);
                m.put("rabinPKH", hex(nft.getRabinPKH()));
            }
            case PP1FtScriptInfo ft -> {
                putCommon(m, ft.getOwnerPKH(), ft.getTokenId(), "pp1_ft", networkAddressType);
                m.put("rabinPKH", hex(ft.getRabinPubKeyHash()));
                m.put("amount", ft.getAmount());
            }
            case PP1AtScriptInfo at -> {
                putCommon(m, at.getOwnerPKH(), at.getTokenId(), "pp1_at", networkAddressType);
                m.put("issuerPKH", hex(at.getIssuerPKH()));
                m.put("rabinPKH", hex(at.getRabinPubKeyHash()));
                m.put("stampCount", at.getStampCount());
                m.put("threshold", at.getThreshold());
                m.put("stampsHash", hex(at.getStampsHash()));
            }
            case PP1SmScriptInfo sm -> {
                putCommon(m, sm.getOwnerPKH(), sm.getTokenId(), "pp1_sm", networkAddressType);
                m.put("merchantPKH", hex(sm.getMerchantPKH()));
                m.put("customerPKH", hex(sm.getCustomerPKH()));
                m.put("rabinPKH", hex(sm.getRabinPubKeyHash()));
                m.put("currentState", sm.getCurrentState());
                m.put("milestoneCount", sm.getMilestoneCount());
                m.put("commitmentHash", hex(sm.getCommitmentHash()));
                m.put("transitionBitmask", sm.getTransitionBitmask());
                m.put("timeoutDelta", sm.getTimeoutDelta());
            }
            case PP1RnftScriptInfo rnft -> {
                putCommon(m, rnft.getOwnerPKH(), rnft.getTokenId(), "pp1_rnft", networkAddressType);
                m.put("rabinPKH", hex(rnft.getRabinPKH()));
                m.put("flags", rnft.getFlags());
            }
            case PP1RftScriptInfo rft -> {
                putCommon(m, rft.getOwnerPKH(), rft.getTokenId(), "pp1_rft", networkAddressType);
                m.put("rabinPKH", hex(rft.getRabinPKH()));
                m.put("flags", rft.getFlags());
                m.put("amount", rft.getAmount());
            }
            default -> { /* unrecognized ScriptInfo subclass */ }
        }

        return m;
    }

    private static void putCommon(Map<String, Object> m, byte[] ownerPKH, byte[] tokenId,
                                   String scriptType, NetworkAddressType nat) {
        m.put("scriptType", scriptType);
        m.put("ownerPKH", hex(ownerPKH));
        m.put("ownerAddress", LegacyAddress.fromPubKeyHash(nat, ownerPKH).toBase58());
        m.put("tokenId", hex(tokenId));
    }

    private static String hex(byte[] bytes) {
        return Utils.HEX.encode(bytes);
    }
}
