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
import ssido.core.data.PublicKeyCredentialCreationOptions;
import java.util.Optional;

public final class RegistrationRequest {
    private final String username;
    private final Optional<String> credentialNickname;
    private final ByteArray requestId;
    private final PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions;

    @JsonCreator
    public RegistrationRequest(
            @JsonProperty("username") String username, 
            @JsonProperty("credentialNickname") Optional<String> credentialNickname, 
            @JsonProperty("requestId") ByteArray requestId, 
            @JsonProperty("publicKeyCredentialCreationOptions") PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions) {
        this.username = username;
        this.credentialNickname = credentialNickname;
        this.requestId = requestId;
        this.publicKeyCredentialCreationOptions = publicKeyCredentialCreationOptions;
    }

    public String getUsername() {
        return this.username;
    }

    public Optional<String> getCredentialNickname() {
        return this.credentialNickname;
    }

    public ByteArray getRequestId() {
        return this.requestId;
    }

    public PublicKeyCredentialCreationOptions getPublicKeyCredentialCreationOptions() {
        return this.publicKeyCredentialCreationOptions;
    }
}
