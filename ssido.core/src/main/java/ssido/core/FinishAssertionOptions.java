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

import ssido.core.data.AuthenticatorAssertionResponse;
import ssido.core.data.ByteArray;
import ssido.core.data.ClientAssertionExtensionOutputs;
import ssido.core.data.PublicKeyCredential;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Parameters for {@link RelyingParty#finishAssertion(FinishAssertionOptions)}.
 */
public final class FinishAssertionOptions {
    /**
     * The request that the {@link #getResponse() response} is a response to.
     */
    @Nonnull
    private final AssertionRequest request;
    /**
     * The client's response to the {@link #getRequest() request}.
     *
     * @see <a href="https://www.w3.org/TR/webauthn/#getAssertion">navigator.credentials.get()</a>
     */
    @Nonnull
    private final PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> response;
    /**
     * The <a href="https://tools.ietf.org/html/rfc8471#section-3.2">token binding ID</a> of the connection to the
     * client, if any.
     *
     * @see <a href="https://tools.ietf.org/html/rfc8471">The Token Binding Protocol Version 1.0</a>
     */
    @Nonnull
    private final Optional<ByteArray> callerTokenBindingId;

    public static FinishAssertionOptionsBuilder.MandatoryStages builder() {
        return new FinishAssertionOptionsBuilder.MandatoryStages();
    }


    public static class FinishAssertionOptionsBuilder {
        private AssertionRequest request;
        private PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> response;
        private Optional<ByteArray> callerTokenBindingId = Optional.empty();


        public static class MandatoryStages {
            private final FinishAssertionOptionsBuilder builder = new FinishAssertionOptionsBuilder();

            public Response request(AssertionRequest request) {
                builder.request(request);
                return new Response();
            }


            public class Response {
                public FinishAssertionOptionsBuilder response(PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> response) {
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
        public FinishAssertionOptionsBuilder callerTokenBindingId(@Nonnull Optional<ByteArray> callerTokenBindingId) {
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
        public FinishAssertionOptionsBuilder callerTokenBindingId(@Nonnull ByteArray callerTokenBindingId) {
            return this.callerTokenBindingId(Optional.of(callerTokenBindingId));
        }

        FinishAssertionOptionsBuilder() {
        }

        /**
         * The request that the {@link #getResponse() response} is a response to.
         * @param request
         * @return 
         */
        public FinishAssertionOptionsBuilder request(@Nonnull final AssertionRequest request) {
            this.request = request;
            return this;
        }

        /**
         * The client's response to the {@link #getRequest() request}.
         *
         * @param response
         * @return 
         * @see <a href="https://www.w3.org/TR/webauthn/#getAssertion">navigator.credentials.get()</a>
         */
        public FinishAssertionOptionsBuilder response(@Nonnull final PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> response) {
            this.response = response;
            return this;
        }

        public FinishAssertionOptions build() {
            return new FinishAssertionOptions(request, response, callerTokenBindingId);
        }
    }

    FinishAssertionOptions(@Nonnull final AssertionRequest request, @Nonnull final PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> response, @Nonnull final Optional<ByteArray> callerTokenBindingId) {
        this.request = request;
        this.response = response;
        this.callerTokenBindingId = callerTokenBindingId;
    }

    public FinishAssertionOptionsBuilder toBuilder() {
        return new FinishAssertionOptionsBuilder().request(this.request).response(this.response).callerTokenBindingId(this.callerTokenBindingId);
    }

    /**
     * The request that the {@link #getResponse() response} is a response to.
     * @return 
     */
    @Nonnull
    public AssertionRequest getRequest() {
        return this.request;
    }

    /**
     * The client's response to the {@link #getRequest() request}.
     *
     * @return 
     * @see <a href="https://www.w3.org/TR/webauthn/#getAssertion">navigator.credentials.get()</a>
     */
    @Nonnull
    public PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> getResponse() {
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
