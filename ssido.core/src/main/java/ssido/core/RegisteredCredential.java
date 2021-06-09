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

import ssido.core.data.AttestedCredentialData;
import ssido.core.data.AuthenticatorAssertionResponse;
import ssido.core.data.AuthenticatorData;
import ssido.core.data.ByteArray;
import ssido.core.data.PublicKeyCredentialDescriptor;
import ssido.core.data.UserIdentity;
import javax.annotation.Nonnull;

/**
 * An abstraction of a credential registered to a particular user.
 *
 * <p>
 * Instances of this class are not expected to be long-lived, and the library only needs to read them, never write them.
 * You may at your discretion store them directly in your database, or assemble them from other components.
 * </p>
 */
public final class RegisteredCredential {
    /**
     * The <a href="https://www.w3.org/TR/webauthn/#credential-id">credential ID</a> of the
     * credential.
     *
     * @see <a href="https://www.w3.org/TR/webauthn/#credential-id">Credential ID</a>
     * @see RegistrationResult#getKeyId()
     * @see PublicKeyCredentialDescriptor#getId()
     */
    @Nonnull
    private final ByteArray credentialId;
    /**
     * The <a href="https://www.w3.org/TR/webauthn/#user-handle">user handle</a> of the user the
     * credential is registered to.
     *
     * @see <a href="https://www.w3.org/TR/webauthn/#user-handle">User Handle</a>
     * @see UserIdentity#getId()
     */
    @Nonnull
    private final ByteArray userHandle;
    /**
     * The credential public key encoded in COSE_Key format, as defined in Section 7 of <a
     * href="https://tools.ietf.org/html/rfc8152">RFC 8152</a>.
     *
     * <p>
     * This is used to verify the {@link AuthenticatorAssertionResponse#getSignature() signature} in authentication
     * assertions.
     * </p>
     *
     * @see AttestedCredentialData#getCredentialPublicKey()
     * @see RegistrationResult#getPublicKeyCose()
     */
    @Nonnull
    private final ByteArray publicKeyCose;
    /**
     * The stored <a hrefhttps://www.w3.org/TR/webauthn/#signcount">signature count</a> of the
     * credential.
     *
     * <p>
     * This is used to validate the {@link AuthenticatorData#getSignatureCounter() signature counter} in authentication
     * assertions.
     * </p>
     *
     * @see <a href="https://www.w3.org/TR/webauthn/#sec-authenticator-data">§6.1. Authenticator
     * Data</a>
     * @see AuthenticatorData#getSignatureCounter()
     * @see AssertionResult#getSignatureCount()
     */
    private final long signatureCount;

    public static RegisteredCredentialBuilder.MandatoryStages builder() {
        return new RegisteredCredentialBuilder.MandatoryStages();
    }


    public static class RegisteredCredentialBuilder {
        private ByteArray credentialId;
        private ByteArray userHandle;
        private ByteArray publicKeyCose;
        private long signatureCount = 0;


        public static class MandatoryStages {
            private final RegisteredCredentialBuilder builder = new RegisteredCredentialBuilder();

            public StageUserHandle credentialId(ByteArray credentialId) {
                builder.credentialId(credentialId);
                return new StageUserHandle();
            }


            public class StageUserHandle {
                public StagePublicKeyCose userHandle(ByteArray userHandle) {
                    builder.userHandle(userHandle);
                    return new StagePublicKeyCose();
                }
            }


            public class StagePublicKeyCose {
                public RegisteredCredentialBuilder publicKeyCose(ByteArray publicKeyCose) {
                    return builder.publicKeyCose(publicKeyCose);
                }
            }
        }

        RegisteredCredentialBuilder() {
        }

        /**
         * The <a href="https://www.w3.org/TR/webauthn/#credential-id">credential ID</a> of the
         * credential.
         *
         * @param credentialId
         * @return 
         * @see <a href="https://www.w3.org/TR/webauthn/#credential-id">Credential ID</a>
         * @see RegistrationResult#getKeyId()
         * @see PublicKeyCredentialDescriptor#getId()
         */
        public RegisteredCredentialBuilder credentialId(@Nonnull final ByteArray credentialId) {
            this.credentialId = credentialId;
            return this;
        }

        /**
         * The <a href="https://www.w3.org/TR/webauthn/#user-handle">user handle</a> of the user the
         * credential is registered to.
         *
         * @param userHandle
         * @return 
         * @see <a href="https://www.w3.org/TR/webauthn/#user-handle">User Handle</a>
         * @see UserIdentity#getId()
         */
        public RegisteredCredentialBuilder userHandle(@Nonnull final ByteArray userHandle) {
            this.userHandle = userHandle;
            return this;
        }

        /**
         * The credential public key encoded in COSE_Key format, as defined in Section 7 of <a
         * href="https://tools.ietf.org/html/rfc8152">RFC 8152</a>.
         *
         * <p>
         * This is used to verify the {@link AuthenticatorAssertionResponse#getSignature() signature} in authentication
         * assertions.
         * </p>
         *
         * @param publicKeyCose
         * @return 
         * @see AttestedCredentialData#getCredentialPublicKey()
         * @see RegistrationResult#getPublicKeyCose()
         */
        public RegisteredCredentialBuilder publicKeyCose(@Nonnull final ByteArray publicKeyCose) {
            this.publicKeyCose = publicKeyCose;
            return this;
        }

        /**
         * The stored <a href="https://www.w3.org/TR/webauthn/#signcount">signature count</a> of the
         * credential.
         *
         * <p>
         * This is used to validate the {@link AuthenticatorData#getSignatureCounter() signature counter} in authentication
         * assertions.
         * </p>
         *
         * @param signatureCount
         * @return 
         * @see <a href="https://www.w3.org/TR/webauthn/#sec-authenticator-data">§6.1. Authenticator
         * Data</a>
         * @see AuthenticatorData#getSignatureCounter()
         * @see AssertionResult#getSignatureCount()
         */
        public RegisteredCredentialBuilder signatureCount(final long signatureCount) {
            this.signatureCount = signatureCount;
            return this;
        }

        public RegisteredCredential build() {
            return new RegisteredCredential(credentialId, userHandle, publicKeyCose, signatureCount);
        }
    }

    public RegisteredCredentialBuilder toBuilder() {
        return new RegisteredCredentialBuilder()
                .credentialId(this.credentialId)
                .userHandle(this.userHandle)
                .publicKeyCose(this.publicKeyCose)
                .signatureCount(this.signatureCount);
    }

    /**
     * The <a href="https://www.w3.org/TR/webauthn/#credential-id">credential ID</a> of the
     * credential.
     *
     * @return
     * @see <a href="https://www.w3.org/TR/webauthn/#credential-id">Credential ID</a>
     * @see RegistrationResult#getKeyId()
     * @see PublicKeyCredentialDescriptor#getId()
     */
    @Nonnull
    public ByteArray getCredentialId() {
        return this.credentialId;
    }

    /**
     * The <a href="https://www.w3.org/TR/webauthn/#user-handle">user handle</a> of the user the
     * credential is registered to.
     *
     * @return 
     * @see <a href="https://www.w3.org/TR/webauthn/#user-handle">User Handle</a>
     * @see UserIdentity#getId()
     */
    @Nonnull
    public ByteArray getUserHandle() {
        return this.userHandle;
    }

    /**
     * The credential public key encoded in COSE_Key format, as defined in Section 7 of <a
     * href="https://tools.ietf.org/html/rfc8152">RFC 8152</a>.
     *
     * <p>
     * This is used to verify the {@link AuthenticatorAssertionResponse#getSignature() signature} in authentication
     * assertions.
     * </p>
     *
     * @return 
     * @see AttestedCredentialData#getCredentialPublicKey()
     * @see RegistrationResult#getPublicKeyCose()
     */
    @Nonnull
    public ByteArray getPublicKeyCose() {
        return this.publicKeyCose;
    }

    /**
     * The stored <a href="https://www.w3.org/TR/webauthn/#signcount">signature count</a> of the
     * credential.
     *
     * <p>
     * This is used to validate the {@link AuthenticatorData#getSignatureCounter() signature counter} in authentication
     * assertions.
     * </p>
     *
     * @return 
     * @see <a href="https://www.w3.org/TR/webauthn/#sec-authenticator-data">§6.1. Authenticator
     * Data</a>
     * @see AuthenticatorData#getSignatureCounter()
     * @see AssertionResult#getSignatureCount()
     */
    public long getSignatureCount() {
        return this.signatureCount;
    }

    private RegisteredCredential(@Nonnull final ByteArray credentialId, @Nonnull final ByteArray userHandle, @Nonnull final ByteArray publicKeyCose, final long signatureCount) {

        this.credentialId = credentialId;
        this.userHandle = userHandle;
        this.publicKeyCose = publicKeyCose;
        this.signatureCount = signatureCount;
    }
}
