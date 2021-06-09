// Copyright (c) 2018, Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package ssido.authenticator;

import com.upokecenter.cbor.CBORObject;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import net.i2p.crypto.eddsa.EdDSAPublicKey;


public final class AuthenticatorCodec {

    public static byte[] publicKeyToCose(PublicKey key) {
        Map<Long, Object> coseKey = new HashMap<>();

        coseKey.put(1L, 1L);  // Key type: octet key pair
        coseKey.put(3L, -8);  // EdDSA(-8)
        coseKey.put(-1L, 6L); // crv: Ed25519
        coseKey.put(-2L, key.getEncoded());

        return CBORObject.FromObject(coseKey).EncodeToBytes();
    }
    
    public static PublicKey coseToPublicKey(CBORObject cose) {
        byte[] encoded = cose.get(CBORObject.FromObject(-2)).GetByteString();

        try {
            X509EncodedKeySpec decoded = new X509EncodedKeySpec(encoded);
            return new EdDSAPublicKey(decoded);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }
}
