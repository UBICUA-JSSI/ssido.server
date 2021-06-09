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

import ssido.core.data.AssertionExtensionInputs;
import ssido.core.data.PublicKeyCredentialRequestOptions;
import ssido.core.data.UserVerificationRequirement;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Parameters for {@link RelyingParty#startAssertion(StartAssertionOptions)}.
 */
public final class StartAssertionOptions {
    /**
     * The username of the user to authenticate, if the user has already been identified.
     * <p>
     * If this is absent, that implies a first-factor authentication operation - meaning identification of the user is
     * deferred until after receiving the response from the client.
     * </p>
     *
     * <p>
     * The default is empty (absent).
     * </p>
     *
     * @see <a href="https://www.w3.org/TR/webauthn/#client-side-resident-public-key-credential-source">Client-side-resident
     * credential</a>
     */
    @Nonnull
    private final Optional<String> username;
    /**
     * Extension inputs for this authentication operation.
     * <p>
     * If {@link RelyingParty#getAppId()} is set, {@link RelyingParty#startAssertion(StartAssertionOptions)} will
     * overwrite any {@link AssertionExtensionInputs#getAppid() appId} extension input set herein.
     * </p>
     *
     * <p>
     * The default specifies no extension inputs.
     * </p>
     */
    @Nonnull
    private final AssertionExtensionInputs extensions;
    /**
     * The value for {@link PublicKeyCredentialRequestOptions#getUserVerification()} for this authentication operation.
     * <p>
     * The default is {@link UserVerificationRequirement#PREFERRED}.
     * </p>
     */
    @Nonnull
    private final Optional<UserVerificationRequirement> userVerification;
    /**
     * The value for {@link PublicKeyCredentialRequestOptions#getTimeout()} for this authentication operation.
     * <p>
     * This library does not take the timeout into account in any way, other than passing it through to the {@link
     * PublicKeyCredentialRequestOptions} so it can be used as an argument to
     * <code>navigator.credentials.get()</code> on the client side.
     * </p>
     * <p>
     * The default is empty.
     * </p>
     */
    @Nonnull
    private final Optional<Long> timeout;


    public static class StartAssertionOptionsBuilder {
        private AssertionExtensionInputs extensions = AssertionExtensionInputs.builder().build();
        @Nonnull
        private Optional<String> username = Optional.empty();
        @Nonnull
        private Optional<UserVerificationRequirement> userVerification = Optional.empty();
        @Nonnull
        private Optional<Long> timeout = Optional.empty();

        /**
         * The username of the user to authenticate, if the user has already been identified.
         * <p>
         * If this is absent, that implies a first-factor authentication operation - meaning identification of the user is
         * deferred until after receiving the response from the client.
         * </p>
         *
         * <p>
         * The default is empty (absent).
         * </p>
         *
         * @param username
         * @return 
         * @see <a href="https://www.w3.org/TR/webauthn/#client-side-resident-public-key-credential-source">Client-side-resident
         * credential</a>
         */
        public StartAssertionOptionsBuilder username(@Nonnull Optional<String> username) {
            this.username = username;
            return this;
        }

        /**
         * The username of the user to authenticate, if the user has already been identified.
         * <p>
         * If this is absent, that implies a first-factor authentication operation - meaning identification of the user is
         * deferred until after receiving the response from the client.
         * </p>
         *
         * <p>
         * The default is empty (absent).
         * </p>
         *
         * @param username
         * @return 
         * @see <a href="https://www.w3.org/TR/webauthn/#client-side-resident-public-key-credential-source">Client-side-resident
         * credential</a>
         */
        public StartAssertionOptionsBuilder username(@Nonnull String username) {
            return this.username(Optional.of(username));
        }

        /**
         * The value for {@link PublicKeyCredentialRequestOptions#getUserVerification()} for this authentication operation.
         * <p>
         * The default is {@link UserVerificationRequirement#PREFERRED}.
         * </p>
         * @param userVerification
         * @return 
         */
        public StartAssertionOptionsBuilder userVerification(@Nonnull Optional<UserVerificationRequirement> userVerification) {
            this.userVerification = userVerification;
            return this;
        }

        /**
         * The value for {@link PublicKeyCredentialRequestOptions#getUserVerification()} for this authentication operation.
         * <p>
         * The default is {@link UserVerificationRequirement#PREFERRED}.
         * </p>
         * @param userVerification
         * @return 
         */
        public StartAssertionOptionsBuilder userVerification(@Nonnull UserVerificationRequirement userVerification) {
            return this.userVerification(Optional.of(userVerification));
        }

        /**
         * The value for {@link PublicKeyCredentialRequestOptions#getTimeout()} for this authentication operation.
         * <p>
         * This library does not take the timeout into account in any way, other than passing it through to the {@link
         * PublicKeyCredentialRequestOptions} so it can be used as an argument to
         * <code>navigator.credentials.get()</code> on the client side.
         * </p>
         * <p>
         * The default is empty.
         * </p>
         * @param timeout
         * @return 
         */
        public StartAssertionOptionsBuilder timeout(@Nonnull Optional<Long> timeout) {
            if (timeout.isPresent() && timeout.get() <= 0) {
                throw new IllegalArgumentException("timeout must be positive, was: " + timeout.get());
            }
            this.timeout = timeout;
            return this;
        }

        /**
         * The value for {@link PublicKeyCredentialRequestOptions#getTimeout()} for this authentication operation.
         * <p>
         * This library does not take the timeout into account in any way, other than passing it through to the {@link
         * PublicKeyCredentialRequestOptions} so it can be used as an argument to
         * <code>navigator.credentials.get()</code> on the client side.
         * </p>
         * <p>
         * The default is empty.
         * </p>
         * @param timeout
         * @return 
         */
        public StartAssertionOptionsBuilder timeout(long timeout) {
            return this.timeout(Optional.of(timeout));
        }

        StartAssertionOptionsBuilder() {
        }

        /**
         * Extension inputs for this authentication operation.
         * <p>
         * If {@link RelyingParty#getAppId()} is set, {@link RelyingParty#startAssertion(StartAssertionOptions)} will
         * overwrite any {@link AssertionExtensionInputs#getAppid() appId} extension input set herein.
         * </p>
         *
         * <p>
         * The default specifies no extension inputs.
         * </p>
         * @param extensions
         * @return 
         */
        public StartAssertionOptionsBuilder extensions(@Nonnull final AssertionExtensionInputs extensions) {
            this.extensions = extensions;
            return this;
        }

        public StartAssertionOptions build() {
            return new StartAssertionOptions(username, extensions, userVerification, timeout);
        }
    }

    StartAssertionOptions(@Nonnull final Optional<String> username, @Nonnull final AssertionExtensionInputs extensions, @Nonnull final Optional<UserVerificationRequirement> userVerification, @Nonnull final Optional<Long> timeout) {
        
        this.username = username;
        this.extensions = extensions;
        this.userVerification = userVerification;
        this.timeout = timeout;
    }

    public static StartAssertionOptionsBuilder builder() {
        return new StartAssertionOptionsBuilder();
    }

    public StartAssertionOptionsBuilder toBuilder() {
        return new StartAssertionOptionsBuilder().username(this.username).extensions(this.extensions).userVerification(this.userVerification).timeout(this.timeout);
    }

    /**
     * The username of the user to authenticate, if the user has already been identified.
     * <p>
     * If this is absent, that implies a first-factor authentication operation - meaning identification of the user is
     * deferred until after receiving the response from the client.
     * </p>
     *
     * <p>
     * The default is empty (absent).
     * </p>
     *
     * @return
     * @see <a href="https://www.w3.org/TR/webauthn/#client-side-resident-public-key-credential-source">Client-side-resident
     * credential</a>
     */
    @Nonnull
    public Optional<String> getUsername() {
        return this.username;
    }

    /**
     * Extension inputs for this authentication operation.
     * <p>
     * If {@link RelyingParty#getAppId()} is set, {@link RelyingParty#startAssertion(StartAssertionOptions)} will
     * overwrite any {@link AssertionExtensionInputs#getAppid() appId} extension input set herein.
     * </p>
     *
     * <p>
     * The default specifies no extension inputs.
     * </p>
     * @return 
     */
    @Nonnull
    public AssertionExtensionInputs getExtensions() {
        return this.extensions;
    }

    /**
     * The value for {@link PublicKeyCredentialRequestOptions#getUserVerification()} for this authentication operation.
     * <p>
     * The default is {@link UserVerificationRequirement#PREFERRED}.
     * </p>
     * @return 
     */
    @Nonnull
    public Optional<UserVerificationRequirement> getUserVerification() {
        return this.userVerification;
    }

    /**
     * The value for {@link PublicKeyCredentialRequestOptions#getTimeout()} for this authentication operation.
     * <p>
     * This library does not take the timeout into account in any way, other than passing it through to the {@link
     * PublicKeyCredentialRequestOptions} so it can be used as an argument to
     * <code>navigator.credentials.get()</code> on the client side.
     * </p>
     * <p>
     * The default is empty.
     * </p>
     * @return 
     */
    @Nonnull
    public Optional<Long> getTimeout() {
        return this.timeout;
    }
}
