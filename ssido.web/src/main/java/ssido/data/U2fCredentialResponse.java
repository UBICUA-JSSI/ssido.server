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
package ssido.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import ssido.core.data.ByteArray;
import javax.annotation.Nonnull;

public final class U2fCredentialResponse {
    private final ByteArray keyHandle;
    private final ByteArray publicKey;
    private final ByteArray attestationCertAndSignature;
    private final ByteArray clientDataJSON;

    @JsonCreator
    public U2fCredentialResponse(@Nonnull @JsonProperty("keyHandle") ByteArray keyHandle, @Nonnull @JsonProperty("publicKey") ByteArray publicKey, @Nonnull @JsonProperty("attestationCertAndSignature") ByteArray attestationCertAndSignature, @Nonnull @JsonProperty("clientDataJSON") ByteArray clientDataJSON) {
        this.keyHandle = keyHandle;
        this.publicKey = publicKey;
        this.attestationCertAndSignature = attestationCertAndSignature;
        this.clientDataJSON = clientDataJSON;
    }

    public ByteArray getKeyHandle() {
        return this.keyHandle;
    }

    public ByteArray getPublicKey() {
        return this.publicKey;
    }

    public ByteArray getAttestationCertAndSignature() {
        return this.attestationCertAndSignature;
    }

    public ByteArray getClientDataJSON() {
        return this.clientDataJSON;
    }
}
