package com.prot.demo;

import android.util.Base64;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

/**
 * Prot — Android 授权保护入口 (EXTENSION_PLAN C1/A1/A2)
 *
 * 用法:
 *   Prot.init(context, getSerialOrAndroidId());
 *   int st = Prot.verifyLicense(serial, licenseText);   // 0 = 有效授权
 *
 * JCA 验签链路: SHA256withRSA (PKCS1 v1.5) + DER SPKI 公钥。
 */
public class Prot {
    private static final String PRODUCT = "PROT-DEMO-2026";
    private static PublicKey sPub = null;

    static {
        System.loadLibrary("prot");
    }

    public static void init(byte[] derPublicKey /* or resource */) throws Exception {
        sPub = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(derPublicKey));
    }

    // ---- JNI native (libprot.so) ----
    private static native int nativeVerifyLicense(String serial, String licenseText);
    private static native int nativeCheckIntegrity();
    private static native int nativeIsDebugged();
    private static native int nativeDetectHook();
    private static native void nativeStartWatchdog();
    private static native void nativeStopWatchdog();

    /** 构建签名载荷 (与 vmenc.license_message / C 侧 license_auth byte-identical). */
    static byte[] buildMessage(byte[] serial, long machineId, int tier, long expires) {
        ByteBuffer b = ByteBuffer.allocate(serial.length + 8 + PRODUCT.length() + 1 + 4)
                .order(ByteOrder.LITTLE_ENDIAN);
        b.put(serial);
        b.putLong(machineId);
        b.put(PRODUCT.getBytes(StandardCharsets.US_ASCII));
        b.put((byte) (tier & 0xFF));
        b.putInt((int) (expires & 0xFFFFFFFFL));
        return b.array();
    }

    /** 完整验签: base64(SIGNATURE) + JCA verify. 返回 0 有效, 1 无效. */
    public static int verifyLicense(String serial, String licenseText, long machineId) {
        if (sPub == null) return 1;
        String sigB64 = null, ser = null, prod = null;
        int tier = 1;
        long expires = 0;
        for (String ln : licenseText.split("\n")) {
            String t = ln.trim();
            int eq = t.indexOf('=');
            if (eq < 0) continue;
            String k = t.substring(0, eq);
            String v = t.substring(eq + 1).trim();
            switch (k) {
                case "SERIAL": ser = v; break;
                case "PRODUCT": prod = v; break;
                case "TIER": tier = Integer.parseInt(v); break;
                case "EXPIRES": expires = Long.parseLong(v); break;
                case "SIGNATURE": sigB64 = v; break;
            }
        }
        if (!serial.equals(ser) || !PRODUCT.equals(prod)) return 1;

        // 试用期控制
        if (expires != 0 && System.currentTimeMillis() / 1000 > expires) return 1;

        byte[] msg = buildMessage(serial.getBytes(StandardCharsets.US_ASCII),
                                  machineId, tier, expires);
        byte[] sig = Base64.decode(sigB64, Base64.DEFAULT);
        try {
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initVerify(sPub);
            s.update(msg);
            return s.verify(sig) ? 0 : 1;
        } catch (Exception e) {
            return 1;
        }
    }

    /** 环境检测汇总: 0 = 干净.
     *  1 = 被调试, 2 = 检测到 hook/Frida, 4 = 完整性失败. */
    public static int envCheck() {
        int flag = 0;
        if (nativeIsDebugged() != 0) flag |= 1;
        if (nativeDetectHook() != 0) flag |= 2;
        if (nativeCheckIntegrity() == 0) flag |= 4;
        return flag;
    }

    public static void startWatchdog() { nativeStartWatchdog(); }
    public static void stopWatchdog() { nativeStopWatchdog(); }
}