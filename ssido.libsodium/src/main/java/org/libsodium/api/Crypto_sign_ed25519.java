/*
 *
 *  * Copyright 2021 UBICUA.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
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
 * @author UBICUA
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
