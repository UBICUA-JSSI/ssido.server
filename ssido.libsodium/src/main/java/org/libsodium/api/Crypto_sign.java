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
import static org.libsodium.jni.SodiumConstants.CRYPTO_SIGN_BYTES;
import static org.libsodium.jni.SodiumConstants.CRYPTO_SIGN_PUBLICKEYBYTES;
import static org.libsodium.jni.SodiumConstants.CRYPTO_SIGN_SECRETKEYBYTES;
import org.libsodium.jni.SodiumException;

/**
 *
 * @author ITON Solutions
 */
public class Crypto_sign extends Crypto{
     
    public static Map<String, byte[]> keypair() throws SodiumException {
        byte[] pk = new byte[CRYPTO_SIGN_PUBLICKEYBYTES];
        byte[] sk = new byte[CRYPTO_SIGN_SECRETKEYBYTES];

        exception(Sodium.crypto_sign_keypair(pk, sk), "crypto_sign_keypair");

        Map<String, byte[]> result = new HashMap<>();
        result.put("pk", pk);
        result.put("sk", sk);

        return result;
    }
    
    public static byte[] sign(byte[] data, byte[] sk) throws SodiumException {
        byte[] cipher = new byte[data.length + CRYPTO_SIGN_BYTES];

        exception(Sodium.crypto_sign(cipher, new int[0], data, data.length, sk), "crypto_sign");
        return cipher;
    }
    
    public static byte[] open(byte[] cipher, byte[] pk) throws SodiumException {
        byte[] data = new byte[cipher.length - CRYPTO_SIGN_BYTES];

        exception(Sodium.crypto_sign_open(data, new int[0], cipher, cipher.length, pk), "crypto_sign_open");
        return data;
    }
    
    public static byte[] detached(byte[] data, byte[] sk) throws SodiumException {
        byte[] sign = new byte[CRYPTO_SIGN_BYTES];

        exception(Sodium.crypto_sign_detached(sign, new int[0], data, data.length, sk), "crypto_sign_detached");
        return sign;
    }
    
    public static boolean verify_detached(byte[] sign, byte[] data, byte[] pk) throws SodiumException {

        exception(Sodium.crypto_sign_verify_detached(sign, data, data.length, pk), "crypto_sign_verify_detached");
        return true;
    }
    
    public static Map<String, byte[]> init() throws SodiumException {
        // FIXME: crypto_sign_init not implemented in libsodium-jni
        throw new SodiumException("Not implemented in libsodium-jni");
    }
    
    public static Map<String, byte[]> update() throws SodiumException {
        // FIXME: crypto_sign_update not implemented in libsodium-jni
        throw new SodiumException("Not implemented in libsodium-jni");
    }
    
    public static Map<String, byte[]> final_create() throws SodiumException {
        // FIXME: crypto_sign_final_create not implemented in libsodium-jni
        throw new SodiumException("Not implemented in libsodium-jni");
    }
    
    public static Map<String, byte[]> final_verify() throws SodiumException {
        // FIXME: crypto_sign_final_verify not implemented in libsodium-jni
        throw new SodiumException("Not implemented in libsodium-jni");
    }
}
