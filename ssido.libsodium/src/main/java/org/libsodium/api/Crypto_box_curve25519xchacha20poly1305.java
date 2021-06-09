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
import static org.libsodium.jni.SodiumConstants.CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_BEFORENMBYTES;
import static org.libsodium.jni.SodiumConstants.CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_PUBLICKEYBYTES;
import static org.libsodium.jni.SodiumConstants.CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_SEALBYTES;
import static org.libsodium.jni.SodiumConstants.CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_SECRETKEYBYTES;
import static org.libsodium.jni.SodiumConstants.CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_TAGBYTES;
import org.libsodium.jni.SodiumException;

/**
 *
 * @author ITON Solutions
 */
public class Crypto_box_curve25519xchacha20poly1305 extends Crypto{
    
    public static Map<String, byte[]> seed_keypair(byte[] seed) throws SodiumException {
        
        byte[] pk = new byte[CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_PUBLICKEYBYTES];
        byte[] sk = new byte[CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_SECRETKEYBYTES];

        exception(Sodium.crypto_box_curve25519xchacha20poly1305_seed_keypair(pk, sk, seed), "crypto_box_curve25519xchacha20poly1305_seed_keypair");
        
        Map<String, byte[]> result = new HashMap<>();
        result.put("pk", pk);
        result.put("sk", sk);

        return result;
    }
    
    public static Map<String, byte[]> keypair() throws SodiumException {
        
        byte[] pk = new byte[CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_PUBLICKEYBYTES];
        byte[] sk = new byte[CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_SECRETKEYBYTES];

        exception(Sodium.crypto_box_curve25519xchacha20poly1305_keypair(pk, sk), "crypto_box_curve25519xchacha20poly1305_keypair");
        
        Map<String, byte[]> result = new HashMap<>();
        result.put("pk", pk);
        result.put("sk", sk);

        return result;
    }
    
    public static byte[] easy(byte[] data, byte[] nonce, byte[] pk, byte[] sk) throws SodiumException {
       
        byte[] cipher = new byte[data.length + CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_TAGBYTES];
        exception(Sodium.crypto_box_curve25519xchacha20poly1305_easy(cipher, data, data.length, nonce, pk, sk), "crypto_box_curve25519xchacha20poly1305_easy");
        return cipher;
    }
    
    public static byte[] open_easy(byte[] cipher, byte[] nonce, byte[] pk, byte[] sk) throws SodiumException {

        byte[] data = new byte[cipher.length - CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_TAGBYTES];
        exception(Sodium.crypto_box_curve25519xchacha20poly1305_open_easy(data, cipher, cipher.length, nonce, pk, sk), "crypto_box_curve25519xchacha20poly1305_open_easy");
        return data;
    }
    
    public static Map<String, byte[]> detached(byte[] data, byte[] nonce, byte[] pk, byte[] sk) throws SodiumException {

        byte[] cipher = new byte[data.length];
        byte[] tag = new byte[CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_TAGBYTES];

        exception(Sodium.crypto_box_curve25519xchacha20poly1305_detached(cipher, tag, data, data.length, nonce, pk, sk), "crypto_box_curve25519xchacha20poly1305_detached");

        Map<String, byte[]> result = new HashMap<>();
        result.put("cipher", cipher);
        result.put("tag", tag);

        return result;
    }
 
    public static byte[] open_detached(byte[] cipher, byte[] tag, byte[] nonce, byte[] pk, byte[] sk) throws SodiumException {

        byte[] data = new byte[cipher.length];

        exception(Sodium.crypto_box_curve25519xchacha20poly1305_open_detached(data, cipher, tag, cipher.length, nonce, pk, sk), "crypto_box_curve25519xchacha20poly1305_open_detached");
        return data;
    }
 
    public static byte[] beforenm(byte[] pk, byte[] sk) throws SodiumException {

        byte[] key = new byte[CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_BEFORENMBYTES];
        exception(Sodium.crypto_box_curve25519xchacha20poly1305_beforenm(key, pk, sk), "crypto_box_curve25519xchacha20poly1305_beforenm");
        return key;
    }
    
    public static byte[] easy_afternm(byte[] data, byte[] nonce, byte[] key) throws SodiumException {
        byte[] cipher = new byte[data.length + CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_TAGBYTES];

        exception(Sodium.crypto_box_curve25519xchacha20poly1305_easy_afternm(cipher, data, data.length, nonce, key), "crypto_box_curve25519xchacha20poly1305_easy_afternm");
        return cipher;
    }
    
    public static byte[] open_easy_afternm(byte[] cipher, byte[] nonce, byte[] key) throws SodiumException {

        byte[] data = new byte[cipher.length - CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_TAGBYTES];

        exception(Sodium.crypto_box_curve25519xchacha20poly1305_open_easy_afternm(data, cipher, cipher.length, nonce, key), "crypto_box_curve25519xchacha20poly1305_open_easy_afternm");
        return data;
    }
    
    public static Map<String, byte[]> detached_afternm(byte[] data, byte[] nonce, byte[] key) throws SodiumException {

        byte[] cipher = new byte[data.length];
        byte[] tag = new byte[CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_TAGBYTES];

        exception(Sodium.crypto_box_curve25519xchacha20poly1305_detached_afternm(cipher, tag, data, data.length, nonce, key), "crypto_box_curve25519xchacha20poly1305_detached_afternm");

        Map<String, byte[]> result = new HashMap<>();
        result.put("cipher", cipher);
        result.put("tag", tag);

        return result;
    }
    
    public static byte[] open_detached_afternm(byte[] cipher, byte[] tag,  byte[] nonce, byte[] key) throws SodiumException {

        byte[] data = new byte[cipher.length];

        exception(Sodium.crypto_box_curve25519xchacha20poly1305_open_detached_afternm(data, cipher, tag, cipher.length, nonce, key), "crypto_box_curve25519xchacha20poly1305_open_detached_afternm");
        return data;
    }
    
    public static byte[] seal(byte[] data, byte[] pk) throws SodiumException {
        byte[] cipher = new byte[data.length + CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_SEALBYTES];

        exception(Sodium.crypto_box_curve25519xchacha20poly1305_seal(cipher, data, data.length, pk), "crypto_box_curve25519xchacha20poly1305_seal");
        return cipher;
    }
    
    public static byte[] seal_open(byte[] cipher, byte[] pk, byte[] sk) throws SodiumException {

        byte[] data = new byte[cipher.length - CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_SEALBYTES];

        exception(Sodium.crypto_box_curve25519xchacha20poly1305_seal_open(data, cipher, cipher.length, pk, sk), "crypto_box_curve25519xchacha20poly1305_seal_open");
        return data;
    }
}
