  
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

import java.nio.ByteBuffer;
import org.libsodium.jni.Sodium;
import org.libsodium.jni.SodiumException;

/**
 *
 * @author UBICUA
 */
public class Crypto_randombytes {
    
    public static byte[] buf(byte[] random) throws SodiumException {
        Sodium.randombytes_buf(random, random.length);
        return random;
    }

    public static byte[] randombytes(byte[] random) throws SodiumException {
        Sodium.randombytes(random, random.length);
        return random;
    }

    public static byte[] buf_deterministic() throws SodiumException {
        // FIXME: randombytes_buf_deterministic not implemented in libsodium-jni
        throw new SodiumException("Not implemented in libsodium-jni");
    }

    public static byte[] random() {
        int random = Sodium.randombytes_random();
        // convert result to long
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES); 
        buffer.putLong(random & 0xFFFFFFFFL);
        return buffer.array();
    }

    public static byte[] randombytes_uniform(int upper_bound) throws SodiumException {
        int random = Sodium.randombytes_uniform(upper_bound);
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES); 
        buffer.putLong(random & 0xFFFFFFFFL);
        return buffer.array();
    }
    
    public static byte[] increment(byte[] nonce) throws SodiumException {
        Sodium.sodium_increment(nonce, nonce.length);
        return nonce;
    }
}
