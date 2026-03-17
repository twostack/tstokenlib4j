package org.twostack.tstokenlib4j.plugin;

import org.twostack.bitcoin4j.Address;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.address.LegacyAddress;
import org.twostack.bitcoin4j.params.NetworkAddressType;
import org.twostack.bitcoin4j.params.NetworkType;
import org.twostack.bitcoin4j.transaction.Transaction;

import java.util.Map;

/**
 * Safe extraction of typed values from a plugin params {@code Map<String, Object>}.
 * Throws {@link IllegalArgumentException} with descriptive messages on missing or invalid values.
 */
final class PluginParamExtractor {

    private PluginParamExtractor() {}

    static String requireString(Map<String, Object> params, String key) {
        Object val = params.get(key);
        if (val == null) {
            throw new IllegalArgumentException("Missing required param '" + key + "'");
        }
        return val.toString();
    }

    static String optionalString(Map<String, Object> params, String key) {
        Object val = params.get(key);
        return val != null ? val.toString() : null;
    }

    static byte[] requireHexBytes(Map<String, Object> params, String key) {
        String hex = requireString(params, key);
        try {
            return Utils.HEX.decode(hex);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid hex in param '" + key + "': " + e.getMessage());
        }
    }

    static byte[] optionalHexBytes(Map<String, Object> params, String key) {
        String hex = optionalString(params, key);
        if (hex == null) return null;
        try {
            return Utils.HEX.decode(hex);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid hex in param '" + key + "': " + e.getMessage());
        }
    }

    static Transaction requireTransaction(Map<String, Object> params, String key) {
        String hex = requireString(params, key);
        try {
            return Transaction.fromHex(hex);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to deserialize transaction from param '" + key + "': " + e.getMessage());
        }
    }

    static long requireLong(Map<String, Object> params, String key) {
        Object val = params.get(key);
        if (val == null) {
            throw new IllegalArgumentException("Missing required param '" + key + "'");
        }
        if (val instanceof Number n) return n.longValue();
        return Long.parseLong(val.toString());
    }

    static long optionalLong(Map<String, Object> params, String key, long defaultVal) {
        Object val = params.get(key);
        if (val == null) return defaultVal;
        if (val instanceof Number n) return n.longValue();
        return Long.parseLong(val.toString());
    }

    static int requireInt(Map<String, Object> params, String key) {
        Object val = params.get(key);
        if (val == null) {
            throw new IllegalArgumentException("Missing required param '" + key + "'");
        }
        if (val instanceof Number n) return n.intValue();
        return Integer.parseInt(val.toString());
    }

    static int optionalInt(Map<String, Object> params, String key, int defaultVal) {
        Object val = params.get(key);
        if (val == null) return defaultVal;
        if (val instanceof Number n) return n.intValue();
        return Integer.parseInt(val.toString());
    }

    static Address requireAddress(Map<String, Object> params, String key, NetworkAddressType nat) {
        String addr = requireString(params, key);
        NetworkType networkType = (nat == NetworkAddressType.MAIN_PKH)
                ? NetworkType.MAIN : NetworkType.TEST;
        return LegacyAddress.fromBase58(networkType, addr);
    }
}
