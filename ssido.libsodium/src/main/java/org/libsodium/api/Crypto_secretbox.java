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
import static org.libsodium.jni.SodiumConstants.CRYPTO_SECRETBOX_KEYBYTES;
import static org.libsodium.jni.SodiumConstants.CRYPTO_SECRETBOX_TAGBYTES;
import org.libsodium.jni.SodiumException;

/**
 *
 * @author UBICUA
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
