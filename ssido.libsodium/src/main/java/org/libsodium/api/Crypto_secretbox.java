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
import static org.libsodium.jni.SodiumConstants.CRYPTO_SECRETBOX_KEYBYTES;
import static org.libsodium.jni.SodiumConstants.CRYPTO_SECRETBOX_TAGBYTES;
import org.libsodium.jni.SodiumException;

/**
 *
 * @author ITON Solutions
 */
public class Crypto_secretbox extends Crypto{
   
    
    
    public static byte[] easy(byte[] data, byte[] nonce, byte[] key) throws SodiumException {
        byte[] cipher = new byte[data.length + CRYPTO_SECRETBOX_TAGBYTES];
        exception(Sodium.crypto_secretbox_easy(cipher, data, data.length, nonce, key), "crypto_secretbox_easy");
        return cipher;
    }
    
    public static byte[] open_easy(byte[] cipher, byte[] nonce, byte[] key) throws SodiumException {
        byte[] data = new byte[cipher.length - CRYPTO_SECRETBOX_TAGBYTES];
        exception(Sodium.crypto_secretbox_open_easy(data, cipher, cipher.length, nonce, key), "crypto_secretbox_open_easy");
        return data;
    }
    
    public static Map<String, byte[]> detached(byte[] data, byte[] nonce, byte[] key) throws SodiumException {
        byte[] cipher = new byte[data.length];
        byte[] tag = new byte[CRYPTO_SECRETBOX_TAGBYTES];

        exception(Sodium.crypto_secretbox_detached(cipher, tag, data, data.length, nonce, key), "crypto_secretbox_detached");

        Map<String, byte[]> result = new HashMap<>();
        result.put("cipher", cipher);
        result.put("tag", tag);

        return result;
    }
    
    public static byte[] open_detached(byte[] cipher, byte[] tag, byte[] nonce, byte[] key) throws SodiumException {
        byte[] data = new byte[cipher.length];
        exception(Sodium.crypto_secretbox_open_detached(data, cipher, tag, cipher.length, nonce, key), "crypto_secretbox_open_detached");
        return data;
    }
    
    public static byte[] keygen() throws SodiumException {
        // FIXME: crypto_auth_keygen not implemented in libsodium-jni, falling back to randombytes_buf
        byte[] key = new byte[CRYPTO_SECRETBOX_KEYBYTES];
        Crypto_randombytes.buf(key);
        return key;
    }
}
