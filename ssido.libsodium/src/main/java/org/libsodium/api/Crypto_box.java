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
import static org.libsodium.jni.SodiumConstants.CRYPTO_BOX_BEFORENMBYTES;
import static org.libsodium.jni.SodiumConstants.CRYPTO_BOX_PUBLICKEYBYTES;
import static org.libsodium.jni.SodiumConstants.CRYPTO_BOX_SEALBYTES;
import static org.libsodium.jni.SodiumConstants.CRYPTO_BOX_SECRETKEYBYTES;
import org.libsodium.jni.SodiumException;
import static org.libsodium.jni.SodiumConstants.CRYPTO_BOX_TAGBYTES;

/**
 *
 * @author UBICUA
 */
public class Crypto_box extends Crypto{
    
    public static Map<String, byte[]> seed_keypair(byte[] seed) throws SodiumException {
        
        byte[] pk = new byte[CRYPTO_BOX_PUBLICKEYBYTES];
        byte[] sk = new byte[CRYPTO_BOX_SECRETKEYBYTES];

        exception(Sodium.crypto_box_seed_keypair(pk, sk, seed), "crypto_box_seed_keypair");
        
        Map<String, byte[]> result = new HashMap<>();
        result.put("pk", pk);
        result.put("sk", sk);

        return result;
    }
    
    public static Map<String, byte[]> keypair() throws SodiumException {
        
        byte[] pk = new byte[CRYPTO_BOX_PUBLICKEYBYTES];
        byte[] sk = new byte[CRYPTO_BOX_SECRETKEYBYTES];

        exception(Sodium.crypto_box_keypair(pk, sk), "crypto_box_keypair");
        
        Map<String, byte[]> result = new HashMap<>();
        result.put("pk", pk);
        result.put("sk", sk);

        return result;
    }
    
    public static byte[] easy(byte[] data, byte[] nonce, byte[] pk, byte[] sk) throws SodiumException {
        byte[] cipher = new byte[data.length + CRYPTO_BOX_TAGBYTES];

        exception(Sodium.crypto_box_easy(cipher, data, data.length, nonce, pk, sk), "crypto_box_easy");
        return cipher;
    }
    
    public static byte[] open_easy(byte[] cipher, byte[] nonce, byte[] pk, byte[] sk) throws SodiumException {
        byte[] data = new byte[cipher.length - CRYPTO_BOX_TAGBYTES];

        exception(Sodium.crypto_box_open_easy(data, cipher, cipher.length, nonce, pk, sk), "crypto_box_open_easy");
        return data;
    }
    
    public static Map<String, byte[]> detached(byte[] data, byte[] nonce, byte[] pk, byte[] sk) throws SodiumException {

        byte[] cipher = new byte[data.length];
        byte[] tag = new byte[CRYPTO_BOX_TAGBYTES];

        exception(Sodium.crypto_box_detached(cipher, tag, data, data.length, nonce, pk, sk), "crypto_box_detached");

        Map<String, byte[]> result = new HashMap<>();
        result.put("cipher", cipher);
        result.put("tag", tag);

        return result;
    }
 
    public static byte[] open_detached(byte[] cipher, byte[] tag, byte[] nonce, byte[] pk, byte[] sk) throws SodiumException {

        byte[] data = new byte[cipher.length];

        exception(Sodium.crypto_box_open_detached(data, cipher, tag, cipher.length, nonce, pk, sk), "crypto_box_open_detached");
        return data;
    }
 
    public static byte[] beforenm(byte[] pk, byte[] sk) throws SodiumException {

        byte[] key = new byte[CRYPTO_BOX_BEFORENMBYTES];

        exception(Sodium.crypto_box_beforenm(key, pk, sk), "crypto_box_beforenm");
        return key;
    }
    
    public static byte[] easy_afternm(byte[] data, byte[] nonce, byte[] key) throws SodiumException {
        byte[] cipher = new byte[data.length + CRYPTO_BOX_TAGBYTES];

        exception(Sodium.crypto_box_easy_afternm(cipher, data, data.length, nonce, key), "crypto_box_easy_afternm");
        return cipher;
    }
    
    public static byte[] open_easy_afternm(byte[] cipher, byte[] nonce, byte[] key) throws SodiumException {
        byte[] data = new byte[cipher.length - CRYPTO_BOX_TAGBYTES];

        exception(Sodium.crypto_box_open_easy_afternm(data, cipher, cipher.length, nonce, key), "crypto_box_open_easy_afternm");
        return data;
    }
    
    public static Map<String, byte[]> detached_afternm(byte[] data, byte[] nonce, byte[] key) throws SodiumException {

        byte[] cipher = new byte[data.length];
        byte[] tag = new byte[CRYPTO_BOX_TAGBYTES];

        exception(Sodium.crypto_box_detached_afternm(cipher, tag, data, data.length, nonce, key), "crypto_box_detached_afternm");

        Map<String, byte[]> result = new HashMap<>();
        result.put("cipher", cipher);
        result.put("tag", tag);

        return result;
    }
    
    public static byte[] open_detached_afternm(byte[] cipher, byte[] tag, byte[] nonce, byte[] key) throws SodiumException {
 
        byte[] data = new byte[cipher.length];

        exception(Sodium.crypto_box_open_detached_afternm(data, cipher, tag, cipher.length, nonce, key), "crypto_box_open_detached_afternm");
        return data;
    }
    
    public static byte[] seal(byte[] data, byte[] pk) throws SodiumException {

        byte[] cipher = new byte[data.length + CRYPTO_BOX_SEALBYTES];

        exception(Sodium.crypto_box_seal(cipher, data, data.length, pk), "crypto_box_seal");
        return cipher;
    }
    
    public static byte[] seal_open(byte[] cipher, byte[] pk, byte[] sk) throws SodiumException {

        byte[] data = new byte[cipher.length - CRYPTO_BOX_SEALBYTES];

        exception(Sodium.crypto_box_seal_open(data, cipher, cipher.length, pk, sk), "crypto_box_seal_open");
        return data;
    }
}
