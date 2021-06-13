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

import static org.libsodium.api.Crypto.exception;
import org.libsodium.jni.Sodium;
import static org.libsodium.jni.SodiumConstants.CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES;
import static org.libsodium.jni.SodiumConstants.CRYPTO_PWHASH_ALG_ARGON2I;
import org.libsodium.jni.SodiumException;

/**
 *
 * @author UBICUA
 */
public class Crypto_pwhash extends Crypto {
    
    public static byte[] pwhash(byte[] credentials, byte[] salt, int opslimit, int memlimit) throws SodiumException {
        
        byte[] hash = new byte[CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES];
        
        exception(Sodium.crypto_pwhash(
                hash,
                hash.length,
                credentials,
                credentials.length,
                salt,
                opslimit,
                memlimit,
                CRYPTO_PWHASH_ALG_ARGON2I), "crypto_pwhash");
        
        return hash;
    }

}
