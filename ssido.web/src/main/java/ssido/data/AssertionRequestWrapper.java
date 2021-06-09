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

import com.fasterxml.jackson.annotation.JsonIgnore;
import ssido.core.AssertionRequest;
import ssido.core.data.ByteArray;
import ssido.core.data.PublicKeyCredentialRequestOptions;
import java.util.Optional;
import javax.annotation.Nonnull;

public final class AssertionRequestWrapper {
    @Nonnull
    private final ByteArray requestId;
    @Nonnull
    private final PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;
    @Nonnull
    private final Optional<String> username;
    @Nonnull
    @JsonIgnore
    private final transient AssertionRequest request;

    public AssertionRequestWrapper(@Nonnull ByteArray requestId, @Nonnull AssertionRequest request) {
        this.requestId = requestId;
        this.publicKeyCredentialRequestOptions = request.getPublicKeyCredentialRequestOptions();
        this.username = request.getUsername();
        this.request = request;
    }

    @Nonnull
    public ByteArray getRequestId() {
        return requestId;
    }

    @Nonnull
    public PublicKeyCredentialRequestOptions getPublicKeyCredentialRequestOptions() {
        return publicKeyCredentialRequestOptions;
    }

    @Nonnull
    public Optional<String> getUsername() {
        return username;
    }

    @Nonnull
    public AssertionRequest getRequest() {
        return request;
    }
}
