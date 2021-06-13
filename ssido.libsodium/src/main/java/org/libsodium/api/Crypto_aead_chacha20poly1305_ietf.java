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
import static org.libsodium.jni.SodiumConstants.CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES;
import static org.libsodium.jni.SodiumConstants.CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES;
import static org.libsodium.jni.SodiumConstants.CRYPTO_AEAD_CHACHA20POLY1305_IETF_TAGBYTES;
import org.libsodium.jni.SodiumException;

/**
 *
 * @author ITON Solutions
 */
public class Crypto_aead_chacha20poly1305_ietf extends Crypto {

    public static byte[] encrypt(byte[] data, byte[] add, byte[] nonce, byte[] key) throws SodiumException {
        byte[] cipher = new byte[data.length + CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES];

        if (add == null) {
            add = new byte[0];
        }

        exception(Sodium.crypto_aead_chacha20poly1305_ietf_encrypt(cipher, new int[0], data, data.length, add, add.length, new byte[0], nonce, key), "crypto_aead_chacha20poly1305_ietf_encrypt");
        return cipher;
    }

    public static byte[] decrypt(byte[] cipher, byte[] add, byte[] nonce, byte[] key) throws SodiumException {

        byte[] data = new byte[cipher.length - CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES];
        if (add == null) {
            add = new byte[0];
        }

        exception(Sodium.crypto_aead_chacha20poly1305_ietf_decrypt(data, new int[0], new byte[0], cipher, cipher.length, add, add.length, nonce, key), "crypto_aead_chacha20poly1305_ietf_decrypt");
        return data;
    }

    public static Map<String, byte[]> encrypt_detached(byte[] data, byte[] add, byte[] nonce, byte[] key) throws SodiumException {
        byte[] cipher = new byte[data.length];
        byte[] tag = new byte[CRYPTO_AEAD_CHACHA20POLY1305_IETF_TAGBYTES];
        if (add == null) {
            add = new byte[0];
        }

        exception(Sodium.crypto_aead_chacha20poly1305_ietf_encrypt_detached(cipher, tag, new int[0], data, data.length, add, add.length, new byte[0], nonce, key), "crypto_aead_chacha20poly1305_ietf_encrypt_detached");
        Map<String, byte[]> result = new HashMap<>();
        result.put("cipher", cipher);
        result.put("tag", tag);
        return result;
    }

    public static byte[] decrypt_detached(byte[] cipher, byte[] tag, byte[] add, byte[] nonce, byte[] key) throws SodiumException {
        
        byte[] data = new byte[cipher.length];
        if (add == null) {
            add = new byte[0];
        }

        exception(Sodium.crypto_aead_chacha20poly1305_ietf_decrypt_detached(data, new byte[0], cipher, cipher.length, tag, add, add.length, nonce, key), "crypto_aead_chacha20poly1305_ietf_decrypt_detached");
        return data;
    }

    public static byte[] keygen() throws SodiumException {
        byte[] key = new byte[CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES];
        Sodium.crypto_aead_chacha20poly1305_ietf_keygen(key);
        return key;
    }
}
