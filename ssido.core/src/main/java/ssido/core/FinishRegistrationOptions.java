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
package ssido.core;

import ssido.core.data.AuthenticatorAttestationResponse;
import ssido.core.data.ByteArray;
import ssido.core.data.ClientRegistrationExtensionOutputs;
import ssido.core.data.PublicKeyCredential;
import ssido.core.data.PublicKeyCredentialCreationOptions;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Parameters for {@link RelyingParty#finishRegistration(FinishRegistrationOptions)}.
 */
public final class FinishRegistrationOptions {
    /**
     * The request that the {@link #getResponse() response} is a response to.
     */
    @Nonnull
    private final PublicKeyCredentialCreationOptions request;
    /**
     * The client's response to the {@link #getRequest() request}.
     *
     * <a href="https://www.w3.org/TR/webauthn/#createCredential">navigator.credentials.create()</a>
     */
    @Nonnull
    private final PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> response;
    /**
     * The <a href="https://tools.ietf.org/html/rfc8471#section-3.2">token binding ID</a> of the connection to the
     * client, if any.
     *
     * @see <a href="https://tools.ietf.org/html/rfc8471">The Token Binding Protocol Version 1.0</a>
     */
    @Nonnull
    private final Optional<ByteArray> callerTokenBindingId;

    public static FinishRegistrationOptionsBuilder.MandatoryStages builder() {
        return new FinishRegistrationOptionsBuilder.MandatoryStages();
    }


    public static class FinishRegistrationOptionsBuilder {
        private PublicKeyCredentialCreationOptions request;
        private PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> response;
        private Optional<ByteArray> callerTokenBindingId = Optional.empty();


        public static class MandatoryStages {
            private final FinishRegistrationOptionsBuilder builder = new FinishRegistrationOptionsBuilder();

            public StageRequest request(PublicKeyCredentialCreationOptions request) {
                builder.request(request);
                return new StageRequest();
            }


            public class StageRequest {
                public FinishRegistrationOptionsBuilder response(PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> response) {
                    return builder.response(response);
                }
            }
        }

        /**
         * The <a href="https://tools.ietf.org/html/rfc8471#section-3.2">token binding ID</a> of the connection to the
         * client, if any.
         *
         * @param callerTokenBindingId
         * @return 
         * @see <a href="https://tools.ietf.org/html/rfc8471">The Token Binding Protocol Version 1.0</a>
         */
        public FinishRegistrationOptionsBuilder callerTokenBindingId(@Nonnull Optional<ByteArray> callerTokenBindingId) {
            this.callerTokenBindingId = callerTokenBindingId;
            return this;
        }

        /**
         * The <a href="https://tools.ietf.org/html/rfc8471#section-3.2">token binding ID</a> of the connection to the
         * client, if any.
         *
         * @param callerTokenBindingId
         * @return 
         * @see <a href="https://tools.ietf.org/html/rfc8471">The Token Binding Protocol Version 1.0</a>
         */
        public FinishRegistrationOptionsBuilder callerTokenBindingId(@Nonnull ByteArray callerTokenBindingId) {
            return this.callerTokenBindingId(Optional.of(callerTokenBindingId));
        }

        FinishRegistrationOptionsBuilder() {
        }

        /**
         * The request that the {@link #getResponse() response} is a response to.
         * @param request
         * @return 
         */
        public FinishRegistrationOptionsBuilder request(@Nonnull final PublicKeyCredentialCreationOptions request) {
            this.request = request;
            return this;
        }

        /**
         * The client's response to the {@link #getRequest() request}.
         *
         * <a href="https://www.w3.org/TR/webauthn/#createCredential">navigator.credentials.create()</a>
         * @param response
         * @return 
         */
        public FinishRegistrationOptionsBuilder response(@Nonnull final PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> response) {
            this.response = response;
            return this;
        }

        public FinishRegistrationOptions build() {
            return new FinishRegistrationOptions(request, response, callerTokenBindingId);
        }
    }

    FinishRegistrationOptions(@Nonnull final PublicKeyCredentialCreationOptions request, @Nonnull final PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> response, @Nonnull final Optional<ByteArray> callerTokenBindingId) {
        this.request = request;
        this.response = response;
        this.callerTokenBindingId = callerTokenBindingId;
    }

    public FinishRegistrationOptionsBuilder toBuilder() {
        return new FinishRegistrationOptionsBuilder().request(this.request).response(this.response).callerTokenBindingId(this.callerTokenBindingId);
    }

    /**
     * The request that the {@link #getResponse() response} is a response to.
     * @return 
     */
    @Nonnull
    public PublicKeyCredentialCreationOptions getRequest() {
        return this.request;
    }

    /**
     * The client's response to the {@link #getRequest() request}.
     *
     * <a href="https://www.w3.org/TR/webauthn/#createCredential">navigator.credentials.create()</a>
     * @return 
     */
    @Nonnull
    public PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> getResponse() {
        return this.response;
    }

    /**
     * The <a href="https://tools.ietf.org/html/rfc8471#section-3.2">token binding ID</a> of the connection to the
     * client, if any.
     *
     * @return 
     * @see <a href="https://tools.ietf.org/html/rfc8471">The Token Binding Protocol Version 1.0</a>
     */
    @Nonnull
    public Optional<ByteArray> getCallerTokenBindingId() {
        return this.callerTokenBindingId;
    }
}
