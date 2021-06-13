  
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
import static org.libsodium.jni.SodiumConstants.CRYPTO_HASH_SHA256;
import org.libsodium.jni.SodiumException;

/**
 *
 * @author UBICUA
 */
public class Crypto_hash_sha256 extends Crypto{
    
    public static byte[] sha256(byte[] message) throws SodiumException  {
        byte[] hash = new byte[CRYPTO_HASH_SHA256];
        exception(Sodium.crypto_hash_sha256(hash, message, message.length), "crypto_hash_sha256");
        return hash;
    }
}
