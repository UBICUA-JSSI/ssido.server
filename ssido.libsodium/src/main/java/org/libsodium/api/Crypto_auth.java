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
import static org.libsodium.jni.SodiumConstants.CRYPTO_AUTH_BYTES;
import static org.libsodium.jni.SodiumConstants.CRYPTO_AUTH_KEYBYTES;
import org.libsodium.jni.SodiumException;

/**
 *
 * @author UBICUA
 */
public class Crypto_auth extends Crypto{

    public static byte[] authenticate(byte[] data, byte[] key) throws SodiumException {
        byte[] cipher = new byte[CRYPTO_AUTH_BYTES];
        exception(Sodium.crypto_auth(cipher, data, data.length, key), "crypto_auth");
        return cipher;
    }
    
    public static boolean verify(byte[] cipher, byte[] data, byte[] key) throws SodiumException {
        exception(Sodium.crypto_auth_verify(cipher, data, data.length, key), "crypto_auth_verify");
        return true;
    }
   
    public static byte[] keygen() throws SodiumException {
        // FIXME: crypto_auth_keygen not implemented in libsodium-jni, falling back to randombytes_buf
        byte[] key = new byte[CRYPTO_AUTH_KEYBYTES];
        Crypto_randombytes.buf(key);
        return key;
    }
}
