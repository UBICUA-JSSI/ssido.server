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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import ssido.util.CollectionUtil;
import ssido.core.data.ByteArray;
import ssido.core.data.PublicKeyCredentialRequestOptions;
import ssido.core.data.UserIdentity;
import ssido.core.data.AuthenticatorData;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * The result of a call to {@link RelyingParty#finishAssertion(FinishAssertionOptions)}.
 */
public final class AssertionResult {
    /**
     * <code>true</code> if the assertion was verified successfully.
     */
    private final boolean success;
    /**
     * The <a href="https://www.w3.org/TR/webauthn/#credential-id">credential ID</a> of the credential
     * used for the assertion.
     *
     * @see <a href="https://www.w3.org/TR/webauthn/#credential-id">Credential ID</a>
     * @see PublicKeyCredentialRequestOptions#getAllowCredentials()
     */
    @Nonnull
    private final ByteArray credentialId;
    /**
     * The <a href="https://www.w3.org/TR/webauthn/#user-handle">user handle</a> of the authenticated
     * user.
     *
     * @see <a href="https://www.w3.org/TR/webauthn/#user-handle">User Handle</a>
     * @see UserIdentity#getId()
     * @see #getUsername()
     */
    @Nonnull
    private final ByteArray userHandle;
    /**
     * The username of the authenticated user.
     *
     * @see #getUserHandle()
     */
    @Nonnull
    private final String username;
    /**
     * The new <a href="https://www.w3.org/TR/webauthn/#signcount">signature count</a> of the
     * credential used for the assertion.
     *
     * <p>
     * You should update this value in your database.
     * </p>
     *
     * @see AuthenticatorData#getSignatureCounter()
     */
    private final long signatureCount;
    /**
     * <code>true</code> if and only if the {@link AuthenticatorData#getSignatureCounter() signature counter value}
     * in the assertion was strictly greater than {@link RegisteredCredential#getSignatureCount() the stored one}.
     *
     * @see <a href="https://www.w3.org/TR/webauthn/#sec-authenticator-data">§6.1. Authenticator
     * Data</a>
     * @see AuthenticatorData#getSignatureCounter()
     * @see RegisteredCredential#getSignatureCount()
     * @see com.yubico.webauthn.RelyingParty.RelyingPartyBuilder#validateSignatureCounter(boolean)
     */
    private final boolean signatureCounterValid;
    /**
     * Zero or more human-readable messages about non-critical issues.
     */
    @Nonnull
    private final List<String> warnings;

    @JsonCreator
    private AssertionResult(
            @JsonProperty("success") boolean success, 
            @Nonnull @JsonProperty("credentialId") ByteArray credentialId, 
            @Nonnull @JsonProperty("userHandle") ByteArray userHandle, 
            @Nonnull @JsonProperty("username") String username, 
            @JsonProperty("signatureCount") long signatureCount, 
            @JsonProperty("signatureCounterValid") boolean signatureCounterValid, 
            @Nonnull @JsonProperty("warnings") List<String> warnings) {
        this.success = success;
        this.credentialId = credentialId;
        this.userHandle = userHandle;
        this.username = username;
        this.signatureCount = signatureCount;
        this.signatureCounterValid = signatureCounterValid;
        this.warnings = CollectionUtil.immutableList(warnings);
    }

    static AssertionResultBuilder.MandatoryStages builder() {
        return new AssertionResultBuilder.MandatoryStages();
    }


    static class AssertionResultBuilder {
        private boolean success;
        private ByteArray credentialId;
        private ByteArray userHandle;
        private String username;
        private long signatureCount;
        private boolean signatureCounterValid;
        private List<String> warnings;


        public static class MandatoryStages {
            private final AssertionResultBuilder builder = new AssertionResultBuilder();

            public StageCredentialId success(boolean success) {
                builder.success(success);
                return new StageCredentialId();
            }


            public class StageCredentialId {
                public StageUserHandle credentialId(ByteArray credentialId) {
                    builder.credentialId(credentialId);
                    return new StageUserHandle();
                }
            }


            public class StageUserHandle {
                public StageUsername userHandle(ByteArray userHandle) {
                    builder.userHandle(userHandle);
                    return new StageUsername();
                }
            }


            public class StageUsername {
                public StageSignatureCount username(String username) {
                    builder.username(username);
                    return new StageSignatureCount();
                }
            }


            public class StageSignatureCount {
                public StageSignatureCounterValid signatureCount(long signatureCount) {
                    builder.signatureCount(signatureCount);
                    return new StageSignatureCounterValid();
                }
            }


            public class StageSignatureCounterValid {
                public StageWarnings signatureCounterValid(boolean signatureCounterValid) {
                    builder.signatureCounterValid(signatureCounterValid);
                    return new StageWarnings();
                }
            }


            public class StageWarnings {
                public AssertionResultBuilder warnings(List<String> warnings) {
                    return builder.warnings(warnings);
                }
            }
        }

        AssertionResultBuilder() {
        }

        /**
         * <code>true</code> if the assertion was verified successfully.
         */
        public AssertionResultBuilder success(final boolean success) {
            this.success = success;
            return this;
        }

        /**
         * The <a href="https://www.w3.org/TR/webauthn/#credential-id">credential ID</a> of the credential
         * used for the assertion.
         *
         * @see <a href="https://www.w3.org/TR/webauthn/#credential-id">Credential ID</a>
         * @see PublicKeyCredentialRequestOptions#getAllowCredentials()
         */
        public AssertionResultBuilder credentialId(@Nonnull final ByteArray credentialId) {
            this.credentialId = credentialId;
            return this;
        }

        /**
         * The <a href="https://www.w3.org/TR/webauthn/#user-handle">user handle</a> of the authenticated
         * user.
         *
         * @see <a href="https://www.w3.org/TR/webauthn/#user-handle">User Handle</a>
         * @see UserIdentity#getId()
         * @see #getUsername()
         */
        public AssertionResultBuilder userHandle(@Nonnull final ByteArray userHandle) {
            this.userHandle = userHandle;
            return this;
        }

        /**
         * The username of the authenticated user.
         *
         * @see #getUserHandle()
         */
        public AssertionResultBuilder username(@Nonnull final String username) {
            this.username = username;
            return this;
        }

        /**
         * The new <a href="https://www.w3.org/TR/webauthn/#signcount">signature count</a> of the
         * credential used for the assertion.
         *
         * <p>
         * You should update this value in your database.
         * </p>
         *
         * @see AuthenticatorData#getSignatureCounter()
         */
        public AssertionResultBuilder signatureCount(final long signatureCount) {
            this.signatureCount = signatureCount;
            return this;
        }

        /**
         * <code>true</code> if and only if the {@link AuthenticatorData#getSignatureCounter() signature counter value}
         * in the assertion was strictly greater than {@link RegisteredCredential#getSignatureCount() the stored one}.
         *
         * @see <a href="https://www.w3.org/TR/webauthn/#sec-authenticator-data">§6.1. Authenticator
         * Data</a>
         * @see AuthenticatorData#getSignatureCounter()
         * @see RegisteredCredential#getSignatureCount()
         * @see com.yubico.webauthn.RelyingParty.RelyingPartyBuilder#validateSignatureCounter(boolean)
         */
        public AssertionResultBuilder signatureCounterValid(final boolean signatureCounterValid) {
            this.signatureCounterValid = signatureCounterValid;
            return this;
        }

        /**
         * Zero or more human-readable messages about non-critical issues.
         */
        public AssertionResultBuilder warnings(@Nonnull final List<String> warnings) {
            this.warnings = warnings;
            return this;
        }

        public AssertionResult build() {
            return new AssertionResult(success, credentialId, userHandle, username, signatureCount, signatureCounterValid, warnings);
        }
    }

    public AssertionResultBuilder toBuilder() {
        return new AssertionResultBuilder().success(this.success).credentialId(this.credentialId).userHandle(this.userHandle).username(this.username).signatureCount(this.signatureCount).signatureCounterValid(this.signatureCounterValid).warnings(this.warnings);
    }

    /**
     * <code>true</code> if the assertion was verified successfully.
     * @return 
     */
    public boolean isSuccess() {
        return this.success;
    }

    /**
     * The <a href="https://www.w3.org/TR/webauthn/#credential-id">credential ID</a> of the credential
     * used for the assertion.
     *
     * @return 
     * @see <a href="https://www.w3.org/TR/webauthn/#credential-id">Credential ID</a>
     * @see PublicKeyCredentialRequestOptions#getAllowCredentials()
     */
    @Nonnull
    public ByteArray getCredentialId() {
        return this.credentialId;
    }

    /**
     * The <a href="https://www.w3.org/TR/webauthn/#user-handle">user handle</a> of the authenticated
     * user.
     *
     * @return 
     * @see <a href="https://www.w3.org/TR/webauthn/#user-handle">User Handle</a>
     * @see UserIdentity#getId()
     * @see #getUsername()
     */
    @Nonnull
    public ByteArray getUserHandle() {
        return this.userHandle;
    }

    /**
     * The username of the authenticated user.
     *
     * @return 
     * @see #getUserHandle()
     */
    @Nonnull
    public String getUsername() {
        return this.username;
    }

    /**
     * The new <a href="https://www.w3.org/TR/webauthn/#signcount">signature count</a> of the
     * credential used for the assertion.
     *
     * <p>
     * You should update this value in your database.
     * </p>
     *
     * @return 
     * @see AuthenticatorData#getSignatureCounter()
     */
    public long getSignatureCount() {
        return this.signatureCount;
    }

    /**
     * <code>true</code> if and only if the {@link AuthenticatorData#getSignatureCounter() signature counter value}
     * in the assertion was strictly greater than {@link RegisteredCredential#getSignatureCount() the stored one}.
     *
     * @return 
     * @see <a href="https://www.w3.org/TR/webauthn/#sec-authenticator-data">§6.1. Authenticator
     * Data</a>
     * @see AuthenticatorData#getSignatureCounter()
     * @see RegisteredCredential#getSignatureCount()
     * @see com.yubico.webauthn.RelyingParty.RelyingPartyBuilder#validateSignatureCounter(boolean)
     */
    public boolean isSignatureCounterValid() {
        return this.signatureCounterValid;
    }

    /**
     * Zero or more human-readable messages about non-critical issues.
     * @return 
     */
    @Nonnull
    public List<String> getWarnings() {
        return this.warnings;
    }
}
