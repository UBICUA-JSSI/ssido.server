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

import org.libsodium.jni.Sodium;
import static org.libsodium.jni.SodiumConstants.CRYPTO_AUTH_HMACSHA256_BYTES;
import static org.libsodium.jni.SodiumConstants.CRYPTO_AUTH_HMACSHA256_KEYBYTES;
import org.libsodium.jni.SodiumException;

/**
 *
 * @author ITON Solutions
 */
public class Crypto_auth_hmacsha256 extends Crypto{
   
    public static byte[] keygen() throws SodiumException {
        // FIXME: crypto_auth_keygen not implemented in libsodium-jni, falling back to randombytes_buf
        byte[] key = new byte[CRYPTO_AUTH_HMACSHA256_KEYBYTES];
        Sodium.randombytes_buf(key, key.length);
        return key;
    }
    
    public static byte[] hmacsha256(byte[] data, byte[] key) throws SodiumException {
        byte[] hash = new byte[CRYPTO_AUTH_HMACSHA256_BYTES];
        exception(Sodium.crypto_auth_hmacsha256(hash, data, data.length, key), "crypto_auth_hmacsha256");
        return hash;
    }
    
     public static boolean verify(byte[] hash, byte[] data, byte[] key) throws SodiumException {
        exception(Sodium.crypto_auth_hmacsha256_verify(hash, data, data.length, key), "crypto_auth_hmacsha256_verify");
        return true;
    }
}
