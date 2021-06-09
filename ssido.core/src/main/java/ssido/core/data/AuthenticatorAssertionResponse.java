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
package ssido.core.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import ssido.core.data.exception.Base64UrlException;
import java.io.IOException;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Represents an authenticator's response to a client’s request for generation of a new authentication assertion given
 * the WebAuthn Relying Party's {@linkplain PublicKeyCredentialRequestOptions#challenge challenge} and OPTIONAL
 * {@linkplain PublicKeyCredentialRequestOptions#allowCredentials list of credentials} it is aware of. This response
 * contains a cryptographic {@linkplain #signature} proving possession of the credential private key, and optionally
 * evidence of user consent to a specific transaction.
 *
 * @see <a href="https://www.w3.org/TR/webauthn/#authenticatorassertionresponse">§5.2.2. Web
 * Authentication Assertion (interface AuthenticatorAssertionResponse)
 * </a>
 */
public final class AuthenticatorAssertionResponse implements AuthenticatorResponse {
    @Nonnull
    private final ByteArray authenticatorData;
    @Nonnull
    private final ByteArray clientDataJSON;
    /**
     * The raw signature returned from the authenticator. See <a href="https://www.w3.org/TR/webauthn/#op-get-assertion">§6.3.3
     * The authenticatorGetAssertion Operation</a>.
     */
    @Nonnull
    private final ByteArray signature;
    /**
     * The user handle returned from the authenticator, or empty if the authenticator did not return a user handle. See
     * <a href="https://www.w3.org/TR/webauthn/#op-get-assertion">§6.3.3 The authenticatorGetAssertion
     * Operation</a>.
     */
    @Nonnull
    private final Optional<ByteArray> userHandle;
    @Nonnull
    private final transient CollectedClientData clientData;

    private AuthenticatorAssertionResponse(
            @Nonnull final ByteArray authenticatorData, 
            @Nonnull final ByteArray clientDataJSON, 
            @Nonnull final ByteArray signature, 
            @Nonnull final Optional<ByteArray> userHandle) throws IOException, Base64UrlException {
        
        this.authenticatorData = authenticatorData;
        this.clientDataJSON = clientDataJSON;
        this.signature = signature;
        this.userHandle = userHandle;
        this.clientData = new CollectedClientData(this.clientDataJSON);
    }

    @JsonCreator
    private AuthenticatorAssertionResponse(@Nonnull @JsonProperty("authenticatorData") final ByteArray authenticatorData, @Nonnull @JsonProperty("clientDataJSON") final ByteArray clientDataJSON, @Nonnull @JsonProperty("signature") final ByteArray signature, @JsonProperty("userHandle") final ByteArray userHandle) throws IOException, Base64UrlException {
        this(authenticatorData, clientDataJSON, signature, Optional.ofNullable(userHandle));
    }

    public static AuthenticatorAssertionResponseBuilder.MandatoryStages builder() {
        return new AuthenticatorAssertionResponseBuilder.MandatoryStages();
    }


    public static class AuthenticatorAssertionResponseBuilder {
        private ByteArray authenticatorData;
        private ByteArray clientDataJSON;
        private ByteArray signature;
        private Optional<ByteArray> userHandle = Optional.empty();


        public static class MandatoryStages {
            private final AuthenticatorAssertionResponseBuilder builder = new AuthenticatorAssertionResponseBuilder();

            public StageAuthenticatorData authenticatorData(ByteArray authenticatorData) {
                builder.authenticatorData(authenticatorData);
                return new StageAuthenticatorData();
            }


            public class StageAuthenticatorData {
                public StageClientData clientDataJSON(ByteArray clientDataJSON) {
                    builder.clientDataJSON(clientDataJSON);
                    return new StageClientData();
                }
            }


            public class StageClientData {
                public AuthenticatorAssertionResponseBuilder signature(ByteArray signature) {
                    return builder.signature(signature);
                }
            }
        }

        /**
         * The user handle returned from the authenticator, or empty if the authenticator did not return a user handle. See
         * <a href="https://www.w3.org/TR/webauthn/#op-get-assertion">§6.3.3 The authenticatorGetAssertion
         * Operation</a>.
         * @param userHandle
         * @return 
         */
        public AuthenticatorAssertionResponseBuilder userHandle(@Nonnull Optional<ByteArray> userHandle) {
            this.userHandle = userHandle;
            return this;
        }

        /**
         * The user handle returned from the authenticator, or empty if the authenticator did not return a user handle. See
         * <a href="https://www.w3.org/TR/webauthn/#op-get-assertion">§6.3.3 The authenticatorGetAssertion
         * Operation</a>.
         * @param userHandle
         * @return 
         */
        public AuthenticatorAssertionResponseBuilder userHandle(@Nonnull ByteArray userHandle) {
            return this.userHandle(Optional.of(userHandle));
        }

        AuthenticatorAssertionResponseBuilder() {
        }

        public AuthenticatorAssertionResponseBuilder authenticatorData(@Nonnull final ByteArray authenticatorData) {
            this.authenticatorData = authenticatorData;
            return this;
        }

        public AuthenticatorAssertionResponseBuilder clientDataJSON(@Nonnull final ByteArray clientDataJSON) {
            this.clientDataJSON = clientDataJSON;
            return this;
        }

        public AuthenticatorAssertionResponseBuilder signature(@Nonnull final ByteArray signature) {
            this.signature = signature;
            return this;
        }

        public AuthenticatorAssertionResponse build() throws IOException, Base64UrlException {
            return new AuthenticatorAssertionResponse(authenticatorData, clientDataJSON, signature, userHandle);
        }
    }

    public AuthenticatorAssertionResponseBuilder toBuilder() {
        return new AuthenticatorAssertionResponseBuilder().authenticatorData(this.authenticatorData).clientDataJSON(this.clientDataJSON).signature(this.signature).userHandle(this.userHandle);
    }

    /**
     * The raw signature returned from the authenticator. See <a href="https://www.w3.org/TR/webauthn/#op-get-assertion">§6.3.3
     * The authenticatorGetAssertion Operation</a>.
     * @return 
     */
    @Nonnull
    public ByteArray getSignature() {
        return this.signature;
    }

    /**
     * The user handle returned from the authenticator, or empty if the authenticator did not return a user handle. See
     * <a href="https://www.w3.org/TR/webauthn/#op-get-assertion">§6.3.3 The authenticatorGetAssertion
     * Operation</a>.
     * @return 
     */
    @Nonnull
    public Optional<ByteArray> getUserHandle() {
        return this.userHandle;
    }

    @Override
    @Nonnull
    public ByteArray getAuthenticatorData() {
        return this.authenticatorData;
    }

    @Override
    @Nonnull
    public ByteArray getClientDataJSON() {
        return this.clientDataJSON;
    }

    @Override
    @Nonnull
    public CollectedClientData getClientData() {
        return this.clientData;
    }
}
