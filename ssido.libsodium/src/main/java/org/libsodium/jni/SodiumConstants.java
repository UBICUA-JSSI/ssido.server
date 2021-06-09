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
package org.libsodium.jni;

public abstract class SodiumConstants {
    
    public final static int CRYPTO_AEAD_CHACHA20POLY1305_ABYTES = 16;
    public final static int CRYPTO_AEAD_CHACHA20POLY1305_TAGBYTES = CRYPTO_AEAD_CHACHA20POLY1305_ABYTES;
    public final static int CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES = 32;
    public final static int CRYPTO_AEAD_CHACHA20POLY1305_NONCEBYTES = 8;
    
    public final static int CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES = 32;
    public final static int CRYPTO_AEAD_CHACHA20POLY1305_IETF_NONCEBYTES = 12;
    public final static int CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES = 16;
    public final static int CRYPTO_AEAD_CHACHA20POLY1305_IETF_TAGBYTES = CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES;
    
    public final static int CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES = 32;
    public final static int CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NONCEBYTES = 24;
    public final static int CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES = 16;
    public final static int CRYPTO_AEAD_XCHACHA20POLY1305_IETF_TAGBYTES = CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES;
    
    public final static int CRYPTO_AUTH_HMACSHA256_BYTES = 32;
    public final static int CRYPTO_AUTH_HMACSHA256_KEYBYTES = 32;
    
    public final static int CRYPTO_AUTH_BYTES = CRYPTO_AUTH_HMACSHA256_BYTES;
    public final static int CRYPTO_AUTH_KEYBYTES = CRYPTO_AUTH_HMACSHA256_KEYBYTES;
    
    public final static int CRYPTO_BOX_PUBLICKEYBYTES = 32;
    public final static int CRYPTO_BOX_SECRETKEYBYTES = 32;
    public final static int CRYPTO_BOX_NONCEBYTES = 24;
    public final static int CRYPTO_BOX_TAGBYTES = 16;
    public final static int CRYPTO_BOX_SEEDBYTES = 32;
    public final static int CRYPTO_BOX_SEALBYTES = CRYPTO_BOX_PUBLICKEYBYTES + CRYPTO_BOX_TAGBYTES;
    public final static int CRYPTO_BOX_BEFORENMBYTES = 32;
    
    public final static int CRYPTO_SECRETBOX_KEYBYTES = 32;
    public final static int CRYPTO_SECRETBOX_TAGBYTES = 16;
    public final static int CRYPTO_SECRETBOX_NONCEBYTES = 24;
    
    public final static int CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_SEEDBYTES = 32;
    public final static int CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_PUBLICKEYBYTES = 32;
    public final static int CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_SECRETKEYBYTES = 32;
    public final static int CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_BEFORENMBYTES = 32;
    public final static int CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_NONCEBYTES = 24;
    public final static int CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_TAGBYTES = 16;
    public final static int CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_SEALBYTES = CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_PUBLICKEYBYTES + CRYPTO_BOX_CURVE25519XCHACHA20POLY1305_TAGBYTES;

    public final static int CRYPTO_SIGN_BYTES = 64;
    public final static int CRYPTO_SIGN_SEEDBYTES = 32;
    public final static int CRYPTO_SIGN_PUBLICKEYBYTES = 32;
    public final static int CRYPTO_SIGN_SECRETKEYBYTES = 64;

    public final static int CRYPTO_SIGN_ED25519_SEEDBYTES = 32;
    public final static int CRYPTO_SIGN_ED25519_PUBLICKEYBYTES = 32;
    public final static int CRYPTO_SIGN_ED25519_SECRETKEYBYTES = 64;
    public final static int CRYPTO_SIGN_ED25519_BYTES = 64;
    public final static int CRYPTO_SIGN_ED25519_SIGNATURE_BYTES = CRYPTO_SIGN_ED25519_BYTES;
    public final static int CRYPTO_SIGN_ED25519_TO_CURVE_BYTES = 32;
    
    ////////////////////////////////////////////////////////////////

    public final static int CRYPTO_PWHASH_ARGON2I_SALTBYTES = 32;
    public final static int CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE = 4;
    public final static int CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE = 33554432;
    public final static int CRYPTO_PWHASH_OPSLIMIT_SENSITIVE = 8;
    public final static int CRYPTO_PWHASH_MEMLIMIT_SENSITIVE = 536870912;
    public final static int CRYPTO_PWHASH_OPSLIMIT_MODERATE = 6;
    public final static int CRYPTO_PWHASH_MEMLIMIT_MODERATE = 134217728;
    public final static int CRYPTO_PWHASH_ALG_ARGON2I = 1;
    public final static int CRYPTO_PWHASH_ALG_DEFAULT = 2;

    public final static int CRYPTO_SHORTHASH_BYTES = 8;
    public final static int CRYPTO_SHORTHASH_KEYBYTES = 16;
    public final static int CRYPTO_GENERICHASH_BYTES = 32;
    public final static int CRYPTO_GENERICHASH_KEYBYTES = 32;
    
    public final static int CRYPTO_HASH_SHA256 = 32;
}
