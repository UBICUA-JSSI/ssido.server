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

import java.nio.ByteBuffer;
import org.libsodium.jni.Sodium;
import org.libsodium.jni.SodiumException;

/**
 *
 * @author ITON Solutions
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
