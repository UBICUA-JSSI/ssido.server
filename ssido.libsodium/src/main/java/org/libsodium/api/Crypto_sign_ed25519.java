/*
 * The MIT License
 *
 * Copyright 2019 ITON Solutions.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.libsodium.api;

import java.util.HashMap;
import java.util.Map;
import org.libsodium.jni.Sodium;
import static org.libsodium.jni.SodiumConstants.CRYPTO_SIGN_ED25519_PUBLICKEYBYTES;
import static org.libsodium.jni.SodiumConstants.CRYPTO_SIGN_ED25519_SECRETKEYBYTES;
import static org.libsodium.jni.SodiumConstants.CRYPTO_SIGN_ED25519_SIGNATURE_BYTES;
import static org.libsodium.jni.SodiumConstants.CRYPTO_SIGN_ED25519_TO_CURVE_BYTES;
import org.libsodium.jni.SodiumException;

/**
 *
 * @author ITON Solutions
 */
public class Crypto_sign_ed25519 extends Crypto{
    
    public static Map<String, byte[]> keypair() throws SodiumException {
        
        byte[] pk = new byte[CRYPTO_SIGN_ED25519_PUBLICKEYBYTES];
        byte[] sk = new byte[CRYPTO_SIGN_ED25519_SECRETKEYBYTES];

        exception(Sodium.crypto_sign_ed25519_keypair(pk, sk), "crypto_sign_ed25519_keypair");
        
        Map<String, byte[]> result = new HashMap<>();
        result.put("pk", pk);
        result.put("sk", sk);

        return result;
    }
    
    public static Map<String, byte[]> seed_keypair(byte[] seed) throws SodiumException {
        
        byte[] pk = new byte[CRYPTO_SIGN_ED25519_PUBLICKEYBYTES];
        byte[] sk = new byte[CRYPTO_SIGN_ED25519_SECRETKEYBYTES];

        exception(Sodium.crypto_sign_ed25519_seed_keypair(pk, sk, seed), "crypto_sign_ed25519_seed_keypair");
        
        Map<String, byte[]> result = new HashMap<>();
        result.put("pk", pk);
        result.put("sk", sk);

        return result;
    }
    
    public static byte[] sk_to_curve25519(byte[] sk) throws SodiumException {
        byte[] curve = new byte[CRYPTO_SIGN_ED25519_TO_CURVE_BYTES];
        exception(Sodium.crypto_sign_ed25519_sk_to_curve25519(curve, sk), "crypto_sign_ed25519_sk_to_curve25519");
        return curve;
    }
    
    public static byte[] pk_to_curve25519(byte[] pk) throws SodiumException {
        byte[] curve = new byte[CRYPTO_SIGN_ED25519_TO_CURVE_BYTES];
        exception(Sodium.crypto_sign_ed25519_pk_to_curve25519(curve, pk), "crypto_sign_ed25519_pk_to_curve25519");
        return curve;
    }
    
    public static byte[] detached(byte[] data, byte[] sk) throws SodiumException {
        byte[] sign = new byte[CRYPTO_SIGN_ED25519_SIGNATURE_BYTES];

        exception(Sodium.crypto_sign_ed25519_detached(sign, new int[0], data, data.length, sk), "crypto_sign_ed25519_detached");
        return sign;
    }
    
    public static boolean verify_detached(byte[] data, byte[] sign, byte[] pk) throws SodiumException {
        
        exception(Sodium.crypto_sign_ed25519_verify_detached(sign, data, data.length, pk), "crypto_sign_ed25519_verify_detached");
        return true;
    }
    
    public static byte[] sign(byte[] data, byte[] sk) throws SodiumException {
        
        byte[] sign = new byte[data.length + CRYPTO_SIGN_ED25519_SIGNATURE_BYTES];
        exception(Sodium.crypto_sign_ed25519(sign, new int[0], data, data.length, sk), "crypto_sign_ed25519");
        return sign;
    }
    
    public static boolean verify(byte[] data, byte[] sign, byte[] pk) throws SodiumException {
        exception(Sodium.crypto_sign_ed25519_open(data, new int[0], sign, sign.length, pk), "crypto_sign_ed25519_open");
        return true;
    }
}
