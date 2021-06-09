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

import ssido.cose.CoseException;
import ssido.util.CollectionUtil;
import ssido.core.data.AuthenticatorAssertionResponse;
import ssido.core.data.ByteArray;
import ssido.core.data.ClientAssertionExtensionOutputs;
import ssido.core.data.CollectedClientData;
import ssido.core.data.PublicKeyCredential;
import ssido.core.data.UserVerificationRequirement;
import ssido.core.exception.InvalidSignatureCountException;
import ssido.core.extension.appid.AppId;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import static ssido.util.ExceptionUtil.assure;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class FinishAssertionSteps {
    private static final Logger LOG = LoggerFactory.getLogger(FinishAssertionSteps.class);
    
    private static final String CLIENT_DATA_TYPE = "webauthn.get";
    private static final BouncyCastleCrypto CRYPTO = new BouncyCastleCrypto();
    private final AssertionRequest request;
    private final PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> response;
    private final Optional<ByteArray> callerTokenBindingId;
    private final Set<String> origins;
    private final String rpId;
    private final CredentialRepository credentialRepository;
    private final boolean validateSignatureCounter;
    private final boolean allowUnrequestedExtensions;

    public Begin begin() {
        return new Begin();
    }

    public AssertionResult run() throws InvalidSignatureCountException {
        return begin().run();
    }

    interface Step<Next extends Step<?>> {
        Next nextStep();

        void validate() throws InvalidSignatureCountException;

        List<String> getPrevWarnings();

        default Optional<AssertionResult> result() {
            return Optional.empty();
        }

        default List<String> getWarnings() {
            return Collections.emptyList();
        }

        default List<String> allWarnings() {
            List<String> result = new ArrayList<>(getPrevWarnings().size() + getWarnings().size());
            result.addAll(getPrevWarnings());
            result.addAll(getWarnings());
            return CollectionUtil.immutableList(result);
        }

        default Next next() throws InvalidSignatureCountException {
            validate();
            return nextStep();
        }

        default AssertionResult run() throws InvalidSignatureCountException {
            if (result().isPresent()) {
                return result().get();
            } else {
                return next().run();
            }
        }
    }

    /**
     * If the allowCredentials option was given when this authentication ceremony was initiated, verify that credential.id identifies one of the public key credentials that were listed in allowCredentials
     */
    final class Begin implements Step<ValidateAllowedCredential> {
        @Override
        public ValidateAllowedCredential nextStep() {
            return new ValidateAllowedCredential(username().get(), userHandle().get(), allWarnings());
        }

        @Override
        public void validate() {
            assure(request.getUsername().isPresent() || response.getResponse().getUserHandle().isPresent(), "At least one of username and user handle must be given; none was.");
            assure(userHandle().isPresent(), "No user found for username: %s, userHandle: %s", request.getUsername(), response.getResponse().getUserHandle());
            assure(username().isPresent(), "No user found for username: %s, userHandle: %s", request.getUsername(), response.getResponse().getUserHandle());
        }

        @Override
        public List<String> getPrevWarnings() {
            return Collections.emptyList();
        }

        private Optional<ByteArray> userHandle() {
            return response.getResponse().getUserHandle().map(Optional::of).orElseGet(() -> credentialRepository.getUserHandleForUsername(request.getUsername().get()));
        }

        private Optional<String> username() {
            return request.getUsername().map(Optional::of).orElseGet(() -> credentialRepository.getUsernameForUserHandle(response.getResponse().getUserHandle().get()));
        }

        public Begin() {
        }

        @Override
        public String toString() {
            return "FinishAssertionSteps.Begin()";
        }
    }

    /**
     * If the allowCredentials option was given when this authentication ceremony was initiated, verify that credential.id identifies one of the public key credentials that were listed in allowCredentials
     */
    final class ValidateAllowedCredential implements Step<ValidateUserHandleCredential> {
        private final String username;
        private final ByteArray userHandle;
        private final List<String> prevWarnings;

        @Override
        public ValidateUserHandleCredential nextStep() {
            return new ValidateUserHandleCredential(username, userHandle, allWarnings());
        }

        @Override
        public void validate() {
            request.getPublicKeyCredentialRequestOptions().getAllowCredentials().ifPresent(allowed -> {
                assure(allowed.stream().anyMatch(allow -> allow.getId().equals(response.getId())), "Unrequested credential ID: %s", response.getId());
            });
        }

        public ValidateAllowedCredential(final String username, 
                final ByteArray userHandle, 
                final List<String> prevWarnings) 
        {
            this.username = username;
            this.userHandle = userHandle;
            this.prevWarnings = prevWarnings;
        }

        public String getUsername() {
            return this.username;
        }

        public ByteArray getUserHandle() {
            return this.userHandle;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishAssertionSteps.ValidateAllowedCredential(username=" + this.getUsername() + ", userHandle=" + this.getUserHandle() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }

    final class ValidateUserHandleCredential implements Step<ValidateRegisteredCredential> {
        private final String username;
        private final ByteArray userHandle;
        private final List<String> prevWarnings;

        @Override
        public ValidateRegisteredCredential nextStep() {
            return new ValidateRegisteredCredential(username, userHandle, allWarnings());
        }

        @Override
        public void validate() {
            Optional<RegisteredCredential> registration = credentialRepository.lookup(response.getId(), userHandle);
            assure(registration.isPresent(), "Unknown credential: %s", response.getId());
            assure(userHandle.equals(registration.get().getUserHandle()), "User handle %s does not own credential %s", userHandle, response.getId());
        }

        public ValidateUserHandleCredential(final String username, final ByteArray userHandle, final List<String> prevWarnings) {
            this.username = username;
            this.userHandle = userHandle;
            this.prevWarnings = prevWarnings;
        }

        public String getUsername() {
            return this.username;
        }

        public ByteArray getUserHandle() {
            return this.userHandle;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishAssertionSteps.ValidateUserHandleCredential(username=" + this.getUsername() + ", userHandle=" + this.getUserHandle() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }

    final class ValidateRegisteredCredential implements Step<ValidateData> {
        private final String username;
        private final ByteArray userHandle;
        private final List<String> prevWarnings;

        @Override
        public ValidateData nextStep() {
            return new ValidateData(username, userHandle, credential(), allWarnings());
        }

        @Override
        public void validate() {
            assure(maybeCredential().isPresent(), "Unknown credential. Credential ID: %s, user handle: %s", response.getId(), userHandle);
        }

        private Optional<RegisteredCredential> maybeCredential() {
            return credentialRepository.lookup(response.getId(), userHandle);
        }

        public RegisteredCredential credential() {
            return maybeCredential().get();
        }

        public ValidateRegisteredCredential(final String username, final ByteArray userHandle, final List<String> prevWarnings) {
            this.username = username;
            this.userHandle = userHandle;
            this.prevWarnings = prevWarnings;
        }

        public String getUsername() {
            return this.username;
        }

        public ByteArray getUserHandle() {
            return this.userHandle;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishAssertionSteps.ValidateRegisteredCredential(username=" + this.getUsername() + ", userHandle=" + this.getUserHandle() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }

    final class ValidateData implements Step<ValidateNoOp> {
        private final String username;
        private final ByteArray userHandle;
        private final RegisteredCredential credential;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            assure(clientData() != null, "Missing client data.");
            assure(authenticatorData() != null, "Missing authenticator data.");
            assure(signature() != null, "Missing signature.");
        }

        @Override
        public ValidateNoOp nextStep() {
            return new ValidateNoOp(username, userHandle, credential, allWarnings());
        }

        public ByteArray authenticatorData() {
            return response.getResponse().getAuthenticatorData();
        }

        public ByteArray clientData() {
            return response.getResponse().getClientDataJSON();
        }

        public ByteArray signature() {
            return response.getResponse().getSignature();
        }

        public ValidateData(final String username, final ByteArray userHandle, final RegisteredCredential credential, final List<String> prevWarnings) {
            this.username = username;
            this.userHandle = userHandle;
            this.credential = credential;
            this.prevWarnings = prevWarnings;
        }

        public String getUsername() {
            return this.username;
        }

        public ByteArray getUserHandle() {
            return this.userHandle;
        }

        public RegisteredCredential getCredential() {
            return this.credential;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishAssertionSteps.ValidateData(username=" + this.getUsername() + ", userHandle=" + this.getUserHandle() + ", credential=" + this.getCredential() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }

    final class ValidateNoOp implements Step<ValidateClientData> {
        private final String username;
        private final ByteArray userHandle;
        private final RegisteredCredential credential;
        private final List<String> prevWarnings;

        // Nothing to do
        @Override
        public void validate() {
        }

        @Override
        public ValidateClientData nextStep() {
            return new ValidateClientData(username, userHandle, credential, allWarnings());
        }

        public ValidateNoOp(final String username, final ByteArray userHandle, final RegisteredCredential credential, final List<String> prevWarnings) {
            this.username = username;
            this.userHandle = userHandle;
            this.credential = credential;
            this.prevWarnings = prevWarnings;
        }

        public String getUsername() {
            return this.username;
        }

        public ByteArray getUserHandle() {
            return this.userHandle;
        }

        public RegisteredCredential getCredential() {
            return this.credential;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishAssertionSteps.ValidateNoOp(username=" + this.getUsername() + ", userHandle=" + this.getUserHandle() + ", credential=" + this.getCredential() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }


    final class ValidateClientData implements Step<ValidateClientDataType> {
        private final String username;
        private final ByteArray userHandle;
        private final RegisteredCredential credential;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            assure(clientData() != null, "Missing client data.");
        }

        @Override
        public ValidateClientDataType nextStep() {
            return new ValidateClientDataType(username, userHandle, credential, clientData(), allWarnings());
        }

        public CollectedClientData clientData() {
            return response.getResponse().getClientData();
        }

        public ValidateClientData(final String username, final ByteArray userHandle, final RegisteredCredential credential, final List<String> prevWarnings) {
            this.username = username;
            this.userHandle = userHandle;
            this.credential = credential;
            this.prevWarnings = prevWarnings;
        }

        public String getUsername() {
            return this.username;
        }

        public ByteArray getUserHandle() {
            return this.userHandle;
        }

        public RegisteredCredential getCredential() {
            return this.credential;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishAssertionSteps.ValidateClientData(username=" + this.getUsername() + ", userHandle=" + this.getUserHandle() + ", credential=" + this.getCredential() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }


    final class ValidateClientDataType implements Step<ValidateChallenge> {
        private final String username;
        private final ByteArray userHandle;
        private final RegisteredCredential credential;
        private final CollectedClientData clientData;
        private final List<String> prevWarnings;
        private final List<String> warnings = new LinkedList<>();

        @Override
        public List<String> getWarnings() {
            return CollectionUtil.immutableList(warnings);
        }

        @Override
        public void validate() {
            assure(CLIENT_DATA_TYPE.equals(clientData.getType()), "The \"type\" in the client data must be exactly \"%s\", was: %s", CLIENT_DATA_TYPE, clientData.getType());
        }

        @Override
        public ValidateChallenge nextStep() {
            return new ValidateChallenge(username, userHandle, credential, allWarnings());
        }

        public ValidateClientDataType(final String username, final ByteArray userHandle, final RegisteredCredential credential, final CollectedClientData clientData, final List<String> prevWarnings) {
            this.username = username;
            this.userHandle = userHandle;
            this.credential = credential;
            this.clientData = clientData;
            this.prevWarnings = prevWarnings;
        }

        public String getUsername() {
            return this.username;
        }

        public ByteArray getUserHandle() {
            return this.userHandle;
        }

        public RegisteredCredential getCredential() {
            return this.credential;
        }

        public CollectedClientData getClientData() {
            return this.clientData;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishAssertionSteps.ValidateClientDataType(username=" + this.getUsername() + ", userHandle=" + this.getUserHandle() + ", credential=" + this.getCredential() + ", clientData=" + this.getClientData() + ", prevWarnings=" + this.getPrevWarnings() + ", warnings=" + this.getWarnings() + ")";
        }
    }


    final class ValidateChallenge implements Step<ValidateOrigin> {
        private final String username;
        private final ByteArray userHandle;
        private final RegisteredCredential credential;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            assure(request.getPublicKeyCredentialRequestOptions().getChallenge().equals(response.getResponse().getClientData().getChallenge()), "Incorrect challenge.");
        }

        @Override
        public ValidateOrigin nextStep() {
            return new ValidateOrigin(username, userHandle, credential, allWarnings());
        }

        public ValidateChallenge(final String username, final ByteArray userHandle, final RegisteredCredential credential, final List<String> prevWarnings) {
            this.username = username;
            this.userHandle = userHandle;
            this.credential = credential;
            this.prevWarnings = prevWarnings;
        }

        public String getUsername() {
            return this.username;
        }

        public ByteArray getUserHandle() {
            return this.userHandle;
        }

        public RegisteredCredential getCredential() {
            return this.credential;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishAssertionSteps.ValidateChallenge(username=" + this.getUsername() + ", userHandle=" + this.getUserHandle() + ", credential=" + this.getCredential() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }


    final class ValidateOrigin implements Step<ValidateTokenBinding> {
        private final String username;
        private final ByteArray userHandle;
        private final RegisteredCredential credential;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            final String responseOrigin;
            responseOrigin = response.getResponse().getClientData().getOrigin();
            if (origins.stream().noneMatch(o -> o.equals(responseOrigin))) {
                throw new IllegalArgumentException("Incorrect origin: " + responseOrigin);
            }
        }

        @Override
        public ValidateTokenBinding nextStep() {
            return new ValidateTokenBinding(username, userHandle, credential, allWarnings());
        }

        public ValidateOrigin(final String username, final ByteArray userHandle, final RegisteredCredential credential, final List<String> prevWarnings) {
            this.username = username;
            this.userHandle = userHandle;
            this.credential = credential;
            this.prevWarnings = prevWarnings;
        }

        public String getUsername() {
            return this.username;
        }

        public ByteArray getUserHandle() {
            return this.userHandle;
        }

        public RegisteredCredential getCredential() {
            return this.credential;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishAssertionSteps.ValidateOrigin(username=" + this.getUsername() + ", userHandle=" + this.getUserHandle() + ", credential=" + this.getCredential() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }

    final class ValidateTokenBinding implements Step<ValidateRpIdHash> {
        private final String username;
        private final ByteArray userHandle;
        private final RegisteredCredential credential;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            TokenBindingValidator.validate(response.getResponse().getClientData().getTokenBinding(), callerTokenBindingId);
        }

        @Override
        public ValidateRpIdHash nextStep() {
            return new ValidateRpIdHash(username, userHandle, credential, allWarnings());
        }

        public ValidateTokenBinding(final String username, final ByteArray userHandle, final RegisteredCredential credential, final List<String> prevWarnings) {
            this.username = username;
            this.userHandle = userHandle;
            this.credential = credential;
            this.prevWarnings = prevWarnings;
        }

        public String getUsername() {
            return this.username;
        }

        public ByteArray getUserHandle() {
            return this.userHandle;
        }

        public RegisteredCredential getCredential() {
            return this.credential;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishAssertionSteps.ValidateTokenBinding(username=" + this.getUsername() + ", userHandle=" + this.getUserHandle() + ", credential=" + this.getCredential() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }


    final class ValidateRpIdHash implements Step<ValidatePresence> {
        private final String username;
        private final ByteArray userHandle;
        private final RegisteredCredential credential;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            try {
                assure(CRYPTO.hash(rpId).equals(response.getResponse().getParsedAuthenticatorData().getRpIdHash()), "Wrong RP ID hash.");
            } catch (IllegalArgumentException e) {
                Optional<AppId> appid = request.getPublicKeyCredentialRequestOptions().getExtensions().getAppid();
                if (appid.isPresent()) {
                    assure(CRYPTO.hash(appid.get().getId()).equals(response.getResponse().getParsedAuthenticatorData().getRpIdHash()), "Wrong RP ID hash.");
                } else {
                    throw e;
                }
            }
        }

        @Override
        public ValidatePresence nextStep() {
            return new ValidatePresence(username, userHandle, credential, allWarnings());
        }

        public ValidateRpIdHash(final String username, final ByteArray userHandle, final RegisteredCredential credential, final List<String> prevWarnings) {
            this.username = username;
            this.userHandle = userHandle;
            this.credential = credential;
            this.prevWarnings = prevWarnings;
        }

        public String getUsername() {
            return this.username;
        }

        public ByteArray getUserHandle() {
            return this.userHandle;
        }

        public RegisteredCredential getCredential() {
            return this.credential;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishAssertionSteps.ValidateRpIdHash(username=" + this.getUsername() + ", userHandle=" + this.getUserHandle() + ", credential=" + this.getCredential() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }


    final class ValidatePresence implements Step<ValidateUserVerification> {
        private final String username;
        private final ByteArray userHandle;
        private final RegisteredCredential credential;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            assure(response.getResponse().getParsedAuthenticatorData().getFlags().UP, "User Presence is required.");
        }

        @Override
        public ValidateUserVerification nextStep() {
            return new ValidateUserVerification(username, userHandle, credential, allWarnings());
        }

        public ValidatePresence(final String username, final ByteArray userHandle, final RegisteredCredential credential, final List<String> prevWarnings) {
            this.username = username;
            this.userHandle = userHandle;
            this.credential = credential;
            this.prevWarnings = prevWarnings;
        }

        public String getUsername() {
            return this.username;
        }

        public ByteArray getUserHandle() {
            return this.userHandle;
        }

        public RegisteredCredential getCredential() {
            return this.credential;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishAssertionSteps.ValidatePresence(username=" + this.getUsername() + ", userHandle=" + this.getUserHandle() + ", credential=" + this.getCredential() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }


    final class ValidateUserVerification implements Step<ValidateExtensions> {
        private final String username;
        private final ByteArray userHandle;
        private final RegisteredCredential credential;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            if (request.getPublicKeyCredentialRequestOptions().getUserVerification() == UserVerificationRequirement.REQUIRED) {
                assure(response.getResponse().getParsedAuthenticatorData().getFlags().UV, "User Verification is required.");
            }
        }

        @Override
        public ValidateExtensions nextStep() {
            return new ValidateExtensions(username, userHandle, credential, allWarnings());
        }

        public ValidateUserVerification(final String username, final ByteArray userHandle, final RegisteredCredential credential, final List<String> prevWarnings) {
            this.username = username;
            this.userHandle = userHandle;
            this.credential = credential;
            this.prevWarnings = prevWarnings;
        }

        public String getUsername() {
            return this.username;
        }

        public ByteArray getUserHandle() {
            return this.userHandle;
        }

        public RegisteredCredential getCredential() {
            return this.credential;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishAssertionSteps.ValidateUserVerification(username=" + this.getUsername() + ", userHandle=" + this.getUserHandle() + ", credential=" + this.getCredential() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }


    final class ValidateExtensions implements Step<ValidateClientHash> {
        private final String username;
        private final ByteArray userHandle;
        private final RegisteredCredential credential;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            if (!allowUnrequestedExtensions) {
                ExtensionsValidation.validate(request.getPublicKeyCredentialRequestOptions().getExtensions(), response);
            }
        }

        @Override
        public List<String> getWarnings() {
            try {
                ExtensionsValidation.validate(request.getPublicKeyCredentialRequestOptions().getExtensions(), response);
                return Collections.emptyList();
            } catch (Exception e) {
                return CollectionUtil.immutableList(Collections.singletonList(e.getMessage()));
            }
        }

        @Override
        public ValidateClientHash nextStep() {
            return new ValidateClientHash(username, userHandle, credential, allWarnings());
        }

        public ValidateExtensions(final String username, final ByteArray userHandle, final RegisteredCredential credential, final List<String> prevWarnings) {
            this.username = username;
            this.userHandle = userHandle;
            this.credential = credential;
            this.prevWarnings = prevWarnings;
        }

        public String getUsername() {
            return this.username;
        }

        public ByteArray getUserHandle() {
            return this.userHandle;
        }

        public RegisteredCredential getCredential() {
            return this.credential;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishAssertionSteps.ValidateExtensions(username=" + this.getUsername() + ", userHandle=" + this.getUserHandle() + ", credential=" + this.getCredential() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }


    final class ValidateClientHash implements Step<ValidateAssertionSignature> {
        private final String username;
        private final ByteArray userHandle;
        private final RegisteredCredential credential;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            assure(clientDataJsonHash().size() == 32, "Failed to compute hash of client data");
        }

        @Override
        public ValidateAssertionSignature nextStep() {
            return new ValidateAssertionSignature(username, userHandle, credential, clientDataJsonHash(), allWarnings());
        }

        public ByteArray clientDataJsonHash() {
            return CRYPTO.hash(response.getResponse().getClientDataJSON());
        }

        public ValidateClientHash(final String username, final ByteArray userHandle, final RegisteredCredential credential, final List<String> prevWarnings) {
            this.username = username;
            this.userHandle = userHandle;
            this.credential = credential;
            this.prevWarnings = prevWarnings;
        }

        public String getUsername() {
            return this.username;
        }

        public ByteArray getUserHandle() {
            return this.userHandle;
        }

        public RegisteredCredential getCredential() {
            return this.credential;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishAssertionSteps.ValidateClientHash(username=" + this.getUsername() + ", userHandle=" + this.getUserHandle() + ", credential=" + this.getCredential() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }

    /**
     * Using the credential public key looked up in step 3, verify that sig is a valid signature over the binary concatenation of authData and hash
     */
    final class ValidateAssertionSignature implements Step<ValidateSignatureCounter> {
        private final String username;
        private final ByteArray userHandle;
        private final RegisteredCredential credential;
        private final ByteArray clientDataJsonHash;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            final ByteArray cose = credential.getPublicKeyCose();
            final PublicKey key;
            try {
                key = WebAuthnCodecs.importCosePublicKey(cose);
            } catch (CoseException | IOException | InvalidKeySpecException e) {
                throw new IllegalArgumentException(String.format("Failed to decode public key: Credential ID: %s COSE: %s", credential.getCredentialId().getBase64Url(), cose.getBase64Url()), e);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            if (!CRYPTO.verifySignature(key, signedBytes(), response.getResponse().getSignature())) {
                throw new IllegalArgumentException("Invalid assertion signature.");
            }
        }

        @Override
        public ValidateSignatureCounter nextStep() {
            return new ValidateSignatureCounter(username, userHandle, allWarnings());
        }

        public ByteArray signedBytes() {
            return response.getResponse().getAuthenticatorData().concat(clientDataJsonHash);
        }

        public ValidateAssertionSignature(final String username, final ByteArray userHandle, final RegisteredCredential credential, final ByteArray clientDataJsonHash, final List<String> prevWarnings) {
            this.username = username;
            this.userHandle = userHandle;
            this.credential = credential;
            this.clientDataJsonHash = clientDataJsonHash;
            this.prevWarnings = prevWarnings;
        }

        public String getUsername() {
            return this.username;
        }

        public ByteArray getUserHandle() {
            return this.userHandle;
        }

        public RegisteredCredential getCredential() {
            return this.credential;
        }

        public ByteArray getClientDataJsonHash() {
            return this.clientDataJsonHash;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishAssertionSteps.ValidateAssertionSignature(username=" + this.getUsername() + ", userHandle=" + this.getUserHandle() + ", credential=" + this.getCredential() + ", clientDataJsonHash=" + this.getClientDataJsonHash() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }

    /**
     * If the signature counter value authData.signCount is nonzero or the value stored in conjunction with credential’s id attribute is nonzero
     */
    final class ValidateSignatureCounter implements Step<Finished> {
        private final String username;
        private final ByteArray userHandle;
        private final List<String> prevWarnings;

        @Override
        public void validate() throws InvalidSignatureCountException {
            if (validateSignatureCounter && !signatureCounterValid()) {
                throw new InvalidSignatureCountException(response.getId(), storedSignatureCountBefore() + 1, assertionSignatureCount());
            }
        }

        private boolean signatureCounterValid() {
            return (assertionSignatureCount() == 0 && storedSignatureCountBefore() == 0) || assertionSignatureCount() > storedSignatureCountBefore();
        }

        @Override
        public Finished nextStep() {
            return new Finished(username, userHandle, assertionSignatureCount(), signatureCounterValid(), allWarnings());
        }

        private long storedSignatureCountBefore() {
            return credentialRepository.lookup(response.getId(), userHandle).map(RegisteredCredential::getSignatureCount).orElse(0L);
        }

        private long assertionSignatureCount() {
            return response.getResponse().getParsedAuthenticatorData().getSignatureCounter();
        }

        public ValidateSignatureCounter(final String username, final ByteArray userHandle, final List<String> prevWarnings) {
            this.username = username;
            this.userHandle = userHandle;
            this.prevWarnings = prevWarnings;
        }

        public String getUsername() {
            return this.username;
        }

        public ByteArray getUserHandle() {
            return this.userHandle;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishAssertionSteps.ValidateSignatureCounter(username=" + this.getUsername() + ", userHandle=" + this.getUserHandle() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }


    final class Finished implements Step<Finished> {
        private final String username;
        private final ByteArray userHandle;
        private final long assertionSignatureCount;
        private final boolean signatureCounterValid;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            /* No-op */ }

        @Override
        public Finished nextStep() {
            return this;
        }

        @Override
        public Optional<AssertionResult> result() {
            return Optional.of(AssertionResult.builder().success(true).credentialId(response.getId()).userHandle(userHandle).username(username).signatureCount(assertionSignatureCount).signatureCounterValid(signatureCounterValid).warnings(allWarnings()).build());
        }

        public Finished(final String username, final ByteArray userHandle, final long assertionSignatureCount, final boolean signatureCounterValid, final List<String> prevWarnings) {
            this.username = username;
            this.userHandle = userHandle;
            this.assertionSignatureCount = assertionSignatureCount;
            this.signatureCounterValid = signatureCounterValid;
            this.prevWarnings = prevWarnings;
        }

        public String getUsername() {
            return this.username;
        }

        public ByteArray getUserHandle() {
            return this.userHandle;
        }

        public long getAssertionSignatureCount() {
            return this.assertionSignatureCount;
        }

        public boolean isSignatureCounterValid() {
            return this.signatureCounterValid;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishAssertionSteps.Finished(username=" + this.getUsername() + ", userHandle=" + this.getUserHandle() + ", assertionSignatureCount=" + this.getAssertionSignatureCount() + ", signatureCounterValid=" + this.isSignatureCounterValid() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }

    FinishAssertionSteps(final AssertionRequest request, 
            final PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> response, 
            final Optional<ByteArray> callerTokenBindingId, 
            final Set<String> origins, 
            final String rpId, 
            final CredentialRepository credentialRepository, 
            final boolean validateSignatureCounter, 
            final boolean allowUnrequestedExtensions) 
    {
        this.request = request;
        this.response = response;
        this.callerTokenBindingId = callerTokenBindingId;
        this.origins = origins;
        this.rpId = rpId;
        this.credentialRepository = credentialRepository;
        this.validateSignatureCounter = validateSignatureCounter;
        this.allowUnrequestedExtensions = allowUnrequestedExtensions;
    }


    public static class FinishAssertionStepsBuilder {
        private AssertionRequest request;
        private PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> response;
        private Optional<ByteArray> callerTokenBindingId;
        private Set<String> origins;
        private String rpId;
        private CredentialRepository credentialRepository;
        private boolean validateSignatureCounter = true;
        private boolean allowUnrequestedExtensions = true;

        FinishAssertionStepsBuilder() {
        }

        public FinishAssertionStepsBuilder request(final AssertionRequest request) {
            this.request = request;
            return this;
        }

        public FinishAssertionStepsBuilder response(final PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> response) {
            this.response = response;
            return this;
        }

        public FinishAssertionStepsBuilder callerTokenBindingId(final Optional<ByteArray> callerTokenBindingId) {
            this.callerTokenBindingId = callerTokenBindingId;
            return this;
        }

        public FinishAssertionStepsBuilder origins(final Set<String> origins) {
            this.origins = origins;
            return this;
        }

        public FinishAssertionStepsBuilder rpId(final String rpId) {
            this.rpId = rpId;
            return this;
        }

        public FinishAssertionStepsBuilder credentialRepository(final CredentialRepository credentialRepository) {
            this.credentialRepository = credentialRepository;
            return this;
        }

        public FinishAssertionStepsBuilder validateSignatureCounter(final boolean validateSignatureCounter) {
            this.validateSignatureCounter = validateSignatureCounter;
            return this;
        }

        public FinishAssertionStepsBuilder allowUnrequestedExtensions(final boolean allowUnrequestedExtensions) {
            this.allowUnrequestedExtensions = allowUnrequestedExtensions;
            return this;
        }

        public FinishAssertionSteps build() {
            return new FinishAssertionSteps(request, response, callerTokenBindingId, origins, rpId, credentialRepository, validateSignatureCounter, allowUnrequestedExtensions);
        }
    }

    public static FinishAssertionStepsBuilder builder() {
        return new FinishAssertionStepsBuilder();
    }
}
