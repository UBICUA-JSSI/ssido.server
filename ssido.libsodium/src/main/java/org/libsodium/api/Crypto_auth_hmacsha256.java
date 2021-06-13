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

import org.libsodium.jni.Sodium;
import static org.libsodium.jni.SodiumConstants.CRYPTO_AUTH_HMACSHA256_BYTES;
import static org.libsodium.jni.SodiumConstants.CRYPTO_AUTH_HMACSHA256_KEYBYTES;
import org.libsodium.jni.SodiumException;

/**
 *
 * @author UBICUA
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
