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

import ssido.core.data.AuthenticatorSelectionCriteria;
import ssido.core.data.PublicKeyCredentialCreationOptions;
import ssido.core.data.RegistrationExtensionInputs;
import ssido.core.data.UserIdentity;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Parameters for {@link RelyingParty#startRegistration(StartRegistrationOptions)}.
 */
public final class StartRegistrationOptions {
    /**
     * Identifiers for the user creating a credential.
     */
    @Nonnull
    private final UserIdentity user;
    /**
     * Constraints on what kind of authenticator the user is allowed to use to create the credential.
     */
    @Nonnull
    private final Optional<AuthenticatorSelectionCriteria> authenticatorSelection;
    /**
     * Extension inputs for this registration operation.
     */
    @Nonnull
    private final RegistrationExtensionInputs extensions;
    /**
     * The value for {@link PublicKeyCredentialCreationOptions#getTimeout()} for this registration operation.
     * <p>
     * This library does not take the timeout into account in any way, other than passing it through to the {@link
     * PublicKeyCredentialCreationOptions} so it can be used as an argument to
     * <code>navigator.credentials.create()</code> on the client side.
     * </p>
     * <p>
     * The default is empty.
     * </p>
     */
    @Nonnull
    private final Optional<Long> timeout;

    public static StartRegistrationOptionsBuilder.MandatoryStages builder() {
        return new StartRegistrationOptionsBuilder.MandatoryStages();
    }


    public static class StartRegistrationOptionsBuilder {
        private UserIdentity user;
        private RegistrationExtensionInputs extensions = RegistrationExtensionInputs.builder().build();
        @Nonnull
        private Optional<AuthenticatorSelectionCriteria> authenticatorSelection = Optional.empty();
        @Nonnull
        private Optional<Long> timeout = Optional.empty();


        public static class MandatoryStages {
            private final StartRegistrationOptionsBuilder builder = new StartRegistrationOptionsBuilder();

            public StartRegistrationOptionsBuilder user(UserIdentity user) {
                return builder.user(user);
            }
        }

        /**
         * Constraints on what kind of authenticator the user is allowed to use to create the credential.
         * @param authenticatorSelection
         * @return 
         */
        public StartRegistrationOptionsBuilder authenticatorSelection(@Nonnull Optional<AuthenticatorSelectionCriteria> authenticatorSelection) {
            this.authenticatorSelection = authenticatorSelection;
            return this;
        }

        /**
         * Constraints on what kind of authenticator the user is allowed to use to create the credential.
         * @param authenticatorSelection
         * @return 
         */
        public StartRegistrationOptionsBuilder authenticatorSelection(@Nonnull AuthenticatorSelectionCriteria authenticatorSelection) {
            return this.authenticatorSelection(Optional.of(authenticatorSelection));
        }

        /**
         * The value for {@link PublicKeyCredentialCreationOptions#getTimeout()} for this registration operation.
         * <p>
         * This library does not take the timeout into account in any way, other than passing it through to the {@link
         * PublicKeyCredentialCreationOptions} so it can be used as an argument to
         * <code>navigator.credentials.create()</code> on the client side.
         * </p>
         * <p>
         * The default is empty.
         * </p>
         * @param timeout
         * @return 
         */
        public StartRegistrationOptionsBuilder timeout(@Nonnull Optional<Long> timeout) {
            if (timeout.isPresent() && timeout.get() <= 0) {
                throw new IllegalArgumentException("timeout must be positive, was: " + timeout.get());
            }
            this.timeout = timeout;
            return this;
        }

        /**
         * The value for {@link PublicKeyCredentialCreationOptions#getTimeout()} for this registration operation.
         * <p>
         * This library does not take the timeout into account in any way, other than passing it through to the {@link
         * PublicKeyCredentialCreationOptions} so it can be used as an argument to
         * <code>navigator.credentials.create()</code> on the client side.
         * </p>
         * <p>
         * The default is empty.
         * </p>
         * @param timeout
         * @return 
         */
        public StartRegistrationOptionsBuilder timeout(long timeout) {
            return this.timeout(Optional.of(timeout));
        }

        StartRegistrationOptionsBuilder() {
        }

        /**
         * Identifiers for the user creating a credential.
         * @param user
         * @return 
         */
        public StartRegistrationOptionsBuilder user(@Nonnull final UserIdentity user) {
            this.user = user;
            return this;
        }

        /**
         * Extension inputs for this registration operation.
         * @param extensions
         * @return 
         */
        public StartRegistrationOptionsBuilder extensions(@Nonnull final RegistrationExtensionInputs extensions) {
            this.extensions = extensions;
            return this;
        }

        public StartRegistrationOptions build() {
            return new StartRegistrationOptions(user, authenticatorSelection, extensions, timeout);
        }
    }

    @java.lang.SuppressWarnings("all")
    private static RegistrationExtensionInputs $default$extensions() {
        return RegistrationExtensionInputs.builder().build();
    }

    StartRegistrationOptions(@Nonnull final UserIdentity user, @Nonnull final Optional<AuthenticatorSelectionCriteria> authenticatorSelection, @Nonnull final RegistrationExtensionInputs extensions, @Nonnull final Optional<Long> timeout) {
        
        this.user = user;
        this.authenticatorSelection = authenticatorSelection;
        this.extensions = extensions;
        this.timeout = timeout;
    }

    public StartRegistrationOptionsBuilder toBuilder() {
        return new StartRegistrationOptionsBuilder().user(this.user).authenticatorSelection(this.authenticatorSelection).extensions(this.extensions).timeout(this.timeout);
    }

    /**
     * Identifiers for the user creating a credential.
     * @return 
     */
    @Nonnull
    public UserIdentity getUser() {
        return this.user;
    }

    /**
     * Constraints on what kind of authenticator the user is allowed to use to create the credential.
     * @return 
     */
    @Nonnull
    public Optional<AuthenticatorSelectionCriteria> getAuthenticatorSelection() {
        return this.authenticatorSelection;
    }

    /**
     * Extension inputs for this registration operation.
     * @return 
     */
    @Nonnull
    public RegistrationExtensionInputs getExtensions() {
        return this.extensions;
    }

    /**
     * The value for {@link PublicKeyCredentialCreationOptions#getTimeout()} for this registration operation.
     * <p>
     * This library does not take the timeout into account in any way, other than passing it through to the {@link
     * PublicKeyCredentialCreationOptions} so it can be used as an argument to
     * <code>navigator.credentials.create()</code> on the client side.
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
