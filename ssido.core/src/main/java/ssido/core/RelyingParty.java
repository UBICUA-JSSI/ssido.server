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

import ssido.core.attestation.MetadataService;
import ssido.core.data.AssertionExtensionInputs;
import ssido.core.data.AttestationConveyancePreference;
import ssido.core.data.AuthenticatorAssertionResponse;
import ssido.core.data.AuthenticatorAttestationResponse;
import ssido.core.data.AuthenticatorData;
import ssido.core.data.ByteArray;
import ssido.core.data.ClientAssertionExtensionOutputs;
import ssido.core.data.ClientRegistrationExtensionOutputs;
import ssido.core.data.CollectedClientData;
import ssido.core.data.PublicKeyCredential;
import ssido.core.data.PublicKeyCredentialCreationOptions;
import ssido.core.data.PublicKeyCredentialCreationOptions.PublicKeyCredentialCreationOptionsBuilder;
import ssido.core.data.PublicKeyCredentialParameters;
import ssido.core.data.PublicKeyCredentialRequestOptions;
import ssido.core.data.PublicKeyCredentialRequestOptions.PublicKeyCredentialRequestOptionsBuilder;
import ssido.core.data.RelyingPartyIdentity;
import ssido.core.exception.AssertionFailedException;
import ssido.core.exception.InvalidSignatureCountException;
import ssido.core.exception.RegistrationFailedException;
import ssido.core.extension.appid.AppId;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import javax.annotation.Nonnull;

/**
 * Encapsulates the four basic Web Authentication operations - start/finish registration, start/finish authentication -
 * along with overall operational settings for them.
 * <p>
 * This class has no mutable state. An instance of this class may therefore be thought of as a container for specialized
 * versions (function closures) of these four operations rather than a stateful object.
 * </p>
 */
public final class RelyingParty {
    private static final SecureRandom RANDOM = new SecureRandom();
    /**
     * The {@link RelyingPartyIdentity} that will be set as the {@link PublicKeyCredentialCreationOptions#getRp() rp}
     * parameter when initiating registration operations, and which {@link AuthenticatorData#getRpIdHash()} will be
     * compared against. This is a required parameter.
     *
     * <p>
     * A successful registration or authentication operation requires {@link AuthenticatorData#getRpIdHash()} to exactly
     * equal the SHA-256 hash of this member's {@link RelyingPartyIdentity#getId() id} member. Alternatively, it may
     * instead equal the SHA-256 hash of {@link #getAppId() appId} if the latter is present.
     * </p>
     *
     * @see #startRegistration(StartRegistrationOptions)
     * @see PublicKeyCredentialCreationOptions
     */
    @Nonnull
    private final RelyingPartyIdentity identity;
    /**
     * The allowed origins that returned authenticator responses will be compared against.
     *
     * <p>
     * The default is the set containing only the string <code>"https://" + {@link #getIdentity()}.getId()</code>.
     * </p>
     *
     * <p>
     * A successful registration or authentication operation requires {@link CollectedClientData#getOrigin()} to exactly
     * equal one of these values.
     * </p>
     *
     * @see #getIdentity()
     */
    @Nonnull
    private final Set<String> origins;
    /**
     * An abstract database which can look up credentials, usernames and user handles from usernames, user handles and
     * credential IDs. This is a required parameter.
     *
     * <p>
     * This is used to look up:
     * </p>
     *
     * <ul>
     * <li>the user handle for a user logging in via user name</li>
     * <li>the user name for a user logging in via user handle</li>
     * <li>the credential IDs to include in {@link PublicKeyCredentialCreationOptions#getExcludeCredentials()}</li>
     * <li>the credential IDs to include in {@link PublicKeyCredentialRequestOptions#getAllowCredentials()}</li>
     * <li>that the correct user owns the credential when verifying an assertion</li>
     * <li>the public key to use to verify an assertion</li>
     * <li>the stored signature counter when verifying an assertion</li>
     * </ul>
     */
    @Nonnull
    private final CredentialRepository credentialRepository;
    /**
     * The extension input to set for the <code>appid</code> extension when initiating authentication operations.
     *
     * <p>
     * If this member is set, {@link #startAssertion(StartAssertionOptions) startAssertion} will automatically set the
     * <code>appid</code> extension input, and {@link #finishAssertion(FinishAssertionOptions) finishAssertion} will
     * adjust its verification logic to also accept this AppID as an alternative to the RP ID.
     * </p>
     *
     * <p>
     * By default, this is not set.
     * </p>
     *
     * @see AssertionExtensionInputs#getAppid()
     * @see <a href="https://www.w3.org/TR/webauthn/#sctn-appid-extension">§10.1. FIDO AppID Extension
     * (appid)</a>
     */
    @Nonnull
    private final Optional<AppId> appId;
    /**
     * The argument for the {@link PublicKeyCredentialCreationOptions#getAttestation() attestation} parameter in
     * registration operations.
     *
     * <p>
     * Unless your application has a concrete policy for authenticator attestation, it is recommended to leave this
     * parameter undefined.
     * </p>
     *
     * <p>
     * By default, this is not set.
     * </p>
     *
     * @see PublicKeyCredentialCreationOptions#getAttestation()
     * @see <a href="https://www.w3.org/TR/webauthn/#sctn-attestation">§6.4. Attestation</a>
     */
    @Nonnull
    private final Optional<AttestationConveyancePreference> attestationConveyancePreference;
    /**
     * A {@link MetadataService} instance to use for looking up device attestation metadata. This matters only if {@link
     * #getAttestationConveyancePreference()} is non-empty and not set to {@link AttestationConveyancePreference#NONE}.
     *
     * <p>
     * By default, this is not set.
     * </p>
     *
     * @see PublicKeyCredentialCreationOptions#getAttestation()
     * @see <a href="https://www.w3.org/TR/webauthn/#sctn-attestation">§6.4. Attestation</a>
     */
    @Nonnull
    private final Optional<MetadataService> metadataService;
    /**
     * The argument for the {@link PublicKeyCredentialCreationOptions#getPubKeyCredParams() pubKeyCredParams} parameter
     * in registration operations.
     *
     * <p>
     * This is a list of acceptable public key algorithms and their parameters, ordered from most to least preferred.
     * </p>
     *
     * <p>
     * The default is the following list:
     * </p>
     *
     * <ol>
     * <li>{@link com.yubico.webauthn.data.PublicKeyCredentialParameters#ES256 ES256}</li>
     * <li>{@link com.yubico.webauthn.data.PublicKeyCredentialParameters#EdDSA EdDSA}</li>
     * <li>{@link com.yubico.webauthn.data.PublicKeyCredentialParameters#RS256 RS256}</li>
     * </ol>
     *
     * @see PublicKeyCredentialCreationOptions#getAttestation()
     * @see <a href="https://www.w3.org/TR/webauthn/#sctn-attestation">§6.4. Attestation</a>
     */
    @Nonnull
    private final List<PublicKeyCredentialParameters> preferredPubkeyParams;
    /**
     * If <code>true</code>, {@link #finishRegistration(FinishRegistrationOptions) finishRegistration} and {@link
     * #finishAssertion(FinishAssertionOptions) finishAssertion} will accept responses containing extension outputs for
     * which there was no extension input.
     *
     * <p>
     * The default is <code>false</code>.
     * </p>
     *
     * @see <a href="https://www.w3.org/TR/webauthn/#extensions">§9. WebAuthn Extensions</a>
     */
    private final boolean allowUnrequestedExtensions;
    /**
     * If <code>false</code>, {@link #finishRegistration(FinishRegistrationOptions) finishRegistration} will only allow
     * registrations where the attestation signature can be linked to a trusted attestation root. This excludes self
     * attestation and none attestation.
     *
     * <p>
     * Regardless of the value of this option, invalid attestation statements of supported formats will always be
     * rejected. For example, a "packed" attestation statement with an invalid signature will be rejected even if this
     * option is set to <code>true</code>.
     * </p>
     *
     * <p>
     * The default is <code>true</code>.
     * </p>
     */
    private final boolean allowUntrustedAttestation;
    /**
     * If <code>true</code>, {@link #finishAssertion(FinishAssertionOptions) finishAssertion} will fail if the {@link
     * AuthenticatorData#getSignatureCounter() signature counter value} in the response is not strictly greater than the
     * {@link RegisteredCredential#getSignatureCount() stored signature counter value}.
     *
     * <p>
     * The default is <code>true</code>.
     * </p>
     */
    private final boolean validateSignatureCounter;

    private RelyingParty(@Nonnull RelyingPartyIdentity identity, Set<String> origins, @Nonnull CredentialRepository credentialRepository, @Nonnull Optional<AppId> appId, @Nonnull Optional<AttestationConveyancePreference> attestationConveyancePreference, @Nonnull Optional<MetadataService> metadataService, List<PublicKeyCredentialParameters> preferredPubkeyParams, boolean allowUnrequestedExtensions, boolean allowUntrustedAttestation, boolean validateSignatureCounter) {
        this.identity = identity;
        this.origins = origins != null ? origins : Collections.singleton("https://" + identity.getId());
        this.credentialRepository = credentialRepository;
        this.appId = appId;
        this.attestationConveyancePreference = attestationConveyancePreference;
        this.metadataService = metadataService;
        this.preferredPubkeyParams = preferredPubkeyParams;
        this.allowUnrequestedExtensions = allowUnrequestedExtensions;
        this.allowUntrustedAttestation = allowUntrustedAttestation;
        this.validateSignatureCounter = validateSignatureCounter;
    }

    private static ByteArray generateChallenge() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return new ByteArray(bytes);
    }

    public PublicKeyCredentialCreationOptions startRegistration(StartRegistrationOptions startRegistrationOptions) {
        PublicKeyCredentialCreationOptionsBuilder builder = PublicKeyCredentialCreationOptions.builder()
                .rp(identity)
                .user(startRegistrationOptions.getUser())
                .challenge(generateChallenge())
                .pubKeyCredParams(preferredPubkeyParams)
                .excludeCredentials(credentialRepository.getCredentialIdsForUsername(startRegistrationOptions.getUser().getName()))
                .authenticatorSelection(startRegistrationOptions.getAuthenticatorSelection())
                .extensions(startRegistrationOptions.getExtensions())
                .timeout(startRegistrationOptions.getTimeout());
        attestationConveyancePreference.ifPresent(builder::attestation);
        return builder.build();
    }

    public RegistrationResult finishRegistration(FinishRegistrationOptions finishRegistrationOptions) throws RegistrationFailedException {
        try {
            return finishRegistration(finishRegistrationOptions.getRequest(), finishRegistrationOptions.getResponse(), finishRegistrationOptions.getCallerTokenBindingId()).run();
        } catch (IllegalArgumentException e) {
            throw new RegistrationFailedException(e);
        }
    }

    /**
     * This method is NOT part of the public API.
     * <p>
     * This method is called internally by {@link #finishRegistration(FinishRegistrationOptions)}. It is a separate
     * method to facilitate testing; users should call {@link #finishRegistration(FinishRegistrationOptions)} instead of
     * this method.
     */
    FinishRegistrationSteps finishRegistration(PublicKeyCredentialCreationOptions request, PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> response, Optional<ByteArray> callerTokenBindingId) {
        return FinishRegistrationSteps.builder()
                .request(request)
                .response(response)
                .callerTokenBindingId(callerTokenBindingId)
                .credentialRepository(credentialRepository)
                .origins(origins)
                .rpId(identity.getId())
                .allowUnrequestedExtensions(allowUnrequestedExtensions)
                .allowUntrustedAttestation(allowUntrustedAttestation)
                .metadataService(metadataService).build();
    }

    public AssertionRequest startAssertion(StartAssertionOptions startAssertionOptions) {
        PublicKeyCredentialRequestOptionsBuilder pkcro = PublicKeyCredentialRequestOptions.builder()
                .challenge(generateChallenge())
                .rpId(identity.getId())
                .allowCredentials(startAssertionOptions.getUsername().map(un -> new ArrayList<>(credentialRepository.getCredentialIdsForUsername(un))))
                .extensions(startAssertionOptions.getExtensions().toBuilder().appid(appId).build()).timeout(startAssertionOptions.getTimeout());
        startAssertionOptions.getUserVerification().ifPresent(pkcro::userVerification);
        return AssertionRequest.builder()
                .publicKeyCredentialRequestOptions(pkcro.build())
                .username(startAssertionOptions.getUsername()).build();
    }

    /**
     * @param finishAssertionOptions
     * @return 
     * @throws InvalidSignatureCountException
     *     if {@link RelyingPartyBuilder#validateSignatureCounter(boolean) validateSignatureCounter} is
     *     <code>true</code>, the {@link AuthenticatorData#getSignatureCounter() signature count} in the response is
     *     less than or equal to the {@link RegisteredCredential#getSignatureCount() stored signature count}, and at
     *     least one of the signature count values is nonzero.
     * @throws AssertionFailedException
     *     if validation fails for any other reason.
     */
    public AssertionResult finishAssertion(FinishAssertionOptions finishAssertionOptions) throws AssertionFailedException {
        try {
            return finishAssertion(finishAssertionOptions.getRequest(), finishAssertionOptions.getResponse(), finishAssertionOptions.getCallerTokenBindingId()).run();
        } catch (IllegalArgumentException e) {
            throw new AssertionFailedException(e);
        }
    }

    /**
     * This method is NOT part of the public API.
     * <p>
     * This method is called internally by {@link #finishAssertion(FinishAssertionOptions)}. It is a separate method to
     * facilitate testing; users should call {@link #finishAssertion(FinishAssertionOptions)} instead of this method.
     */
    FinishAssertionSteps finishAssertion(AssertionRequest request, PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> response, Optional<ByteArray> callerTokenBindingId)  // = None.asJava
    {
        return FinishAssertionSteps.builder()
                .request(request)
                .response(response)
                .callerTokenBindingId(callerTokenBindingId)
                .origins(origins)
                .rpId(identity.getId())
                .credentialRepository(credentialRepository)
                .allowUnrequestedExtensions(allowUnrequestedExtensions)
                .validateSignatureCounter(validateSignatureCounter)
                .build();
    }

    public static RelyingPartyBuilder.MandatoryStages builder() {
        return new RelyingPartyBuilder.MandatoryStages();
    }


    public static class RelyingPartyBuilder {
        private RelyingPartyIdentity identity;
        private Set<String> origins;
        private CredentialRepository credentialRepository;
        private List<PublicKeyCredentialParameters> preferredPubkeyParams = Collections.unmodifiableList(Arrays.asList(PublicKeyCredentialParameters.ES256, PublicKeyCredentialParameters.EdDSA, PublicKeyCredentialParameters.RS256));;
        private boolean allowUnrequestedExtensions = false;
        private boolean allowUntrustedAttestation = true;
        private boolean validateSignatureCounter = true;
        @Nonnull
        private Optional<AppId> appId = Optional.empty();
        @Nonnull
        private Optional<AttestationConveyancePreference> attestationConveyancePreference = Optional.empty();
        @Nonnull
        private Optional<MetadataService> metadataService = Optional.empty();


        public static class MandatoryStages {
            private final RelyingPartyBuilder builder = new RelyingPartyBuilder();

            /**
             * {@link RelyingPartyBuilder#identity(RelyingPartyIdentity) identity} is a required parameter.
             *
             * @param identity
             * @return 
             * @see RelyingPartyBuilder#identity(RelyingPartyIdentity)
             */
            public StageIdentity identity(RelyingPartyIdentity identity) {
                builder.identity(identity);
                return new StageIdentity();
            }


            public class StageIdentity {
                /**
                 * {@link RelyingPartyBuilder#credentialRepository(CredentialRepository) credentialRepository} is a
                 * required parameter.
                 *
                 * @param credentialRepository
                 * @return 
                 * @see RelyingPartyBuilder#credentialRepository(CredentialRepository)
                 */
                public RelyingPartyBuilder credentialRepository(CredentialRepository credentialRepository) {
                    return builder.credentialRepository(credentialRepository);
                }
            }
        }

        /**
         * The extension input to set for the <code>appid</code> extension when initiating authentication operations.
         *
         * <p>
         * If this member is set, {@link #startAssertion(StartAssertionOptions) startAssertion} will automatically set the
         * <code>appid</code> extension input, and {@link #finishAssertion(FinishAssertionOptions) finishAssertion} will
         * adjust its verification logic to also accept this AppID as an alternative to the RP ID.
         * </p>
         *
         * <p>
         * By default, this is not set.
         * </p>
         *
         * @param appId
         * @return 
         * @see AssertionExtensionInputs#getAppid()
         * @see <a href="https://www.w3.org/TR/webauthn/#sctn-appid-extension">§10.1. FIDO AppID Extension
         * (appid)</a>
         */
        public RelyingPartyBuilder appId(@Nonnull Optional<AppId> appId) {
            this.appId = appId;
            return this;
        }

        /**
         * The extension input to set for the <code>appid</code> extension when initiating authentication operations.
         *
         * <p>
         * If this member is set, {@link #startAssertion(StartAssertionOptions) startAssertion} will automatically set the
         * <code>appid</code> extension input, and {@link #finishAssertion(FinishAssertionOptions) finishAssertion} will
         * adjust its verification logic to also accept this AppID as an alternative to the RP ID.
         * </p>
         *
         * <p>
         * By default, this is not set.
         * </p>
         *
         * @param appId
         * @return 
         * @see AssertionExtensionInputs#getAppid()
         * @see <a href="https://www.w3.org/TR/webauthn/#sctn-appid-extension">§10.1. FIDO AppID Extension
         * (appid)</a>
         */
        public RelyingPartyBuilder appId(@Nonnull AppId appId) {
            return this.appId(Optional.of(appId));
        }

        /**
         * The argument for the {@link PublicKeyCredentialCreationOptions#getAttestation() attestation} parameter in
         * registration operations.
         *
         * <p>
         * Unless your application has a concrete policy for authenticator attestation, it is recommended to leave this
         * parameter undefined.
         * </p>
         *
         * <p>
         * By default, this is not set.
         * </p>
         *
         * @param attestationConveyancePreference
         * @return 
         * @see PublicKeyCredentialCreationOptions#getAttestation()
         * @see <a href="https://www.w3.org/TR/webauthn/#sctn-attestation">§6.4. Attestation</a>
         */
        public RelyingPartyBuilder attestationConveyancePreference(@Nonnull Optional<AttestationConveyancePreference> attestationConveyancePreference) {
            this.attestationConveyancePreference = attestationConveyancePreference;
            return this;
        }

        /**
         * The argument for the {@link PublicKeyCredentialCreationOptions#getAttestation() attestation} parameter in
         * registration operations.
         *
         * <p>
         * Unless your application has a concrete policy for authenticator attestation, it is recommended to leave this
         * parameter undefined.
         * </p>
         *
         * <p>
         * By default, this is not set.
         * </p>
         *
         * @param attestationConveyancePreference
         * @return 
         * @see PublicKeyCredentialCreationOptions#getAttestation()
         * @see <a href="https://www.w3.org/TR/webauthn/#sctn-attestation">§6.4. Attestation</a>
         */
        public RelyingPartyBuilder attestationConveyancePreference(@Nonnull AttestationConveyancePreference attestationConveyancePreference) {
            return this.attestationConveyancePreference(Optional.of(attestationConveyancePreference));
        }

        /**
         * A {@link MetadataService} instance to use for looking up device attestation metadata. This matters only if {@link
         * #getAttestationConveyancePreference()} is non-empty and not set to {@link AttestationConveyancePreference#NONE}.
         *
         * <p>
         * By default, this is not set.
         * </p>
         *
         * @param metadataService
         * @return 
         * @see PublicKeyCredentialCreationOptions#getAttestation()
         * @see <a href="https://www.w3.org/TR/webauthn/#sctn-attestation">§6.4. Attestation</a>
         */
        public RelyingPartyBuilder metadataService(@Nonnull Optional<MetadataService> metadataService) {
            this.metadataService = metadataService;
            return this;
        }

        /**
         * A {@link MetadataService} instance to use for looking up device attestation metadata. This matters only if {@link
         * #getAttestationConveyancePreference()} is non-empty and not set to {@link AttestationConveyancePreference#NONE}.
         *
         * <p>
         * By default, this is not set.
         * </p>
         *
         * @param metadataService
         * @return 
         * @see PublicKeyCredentialCreationOptions#getAttestation()
         * @see <a href="https://www.w3.org/TR/webauthn/#sctn-attestation">§6.4. Attestation</a>
         */
        public RelyingPartyBuilder metadataService(@Nonnull MetadataService metadataService) {
            return this.metadataService(Optional.of(metadataService));
        }

        RelyingPartyBuilder() {
        }

        /**
         * The {@link RelyingPartyIdentity} that will be set as the {@link PublicKeyCredentialCreationOptions#getRp() rp}
         * parameter when initiating registration operations, and which {@link AuthenticatorData#getRpIdHash()} will be
         * compared against. This is a required parameter.
         *
         * <p>
         * A successful registration or authentication operation requires {@link AuthenticatorData#getRpIdHash()} to exactly
         * equal the SHA-256 hash of this member's {@link RelyingPartyIdentity#getId() id} member. Alternatively, it may
         * instead equal the SHA-256 hash of {@link #getAppId() appId} if the latter is present.
         * </p>
         *
         * @param identity
         * @return 
         * @see #startRegistration(StartRegistrationOptions)
         * @see PublicKeyCredentialCreationOptions
         */
        public RelyingPartyBuilder identity(@Nonnull final RelyingPartyIdentity identity) {
            this.identity = identity;
            return this;
        }

        /**
         * The allowed origins that returned authenticator responses will be compared against.
         *
         * <p>
         * The default is the set containing only the string <code>"https://" + {@link #getIdentity()}.getId()</code>.
         * </p>
         *
         * <p>
         * A successful registration or authentication operation requires {@link CollectedClientData#getOrigin()} to exactly
         * equal one of these values.
         * </p>
         *
         * @param origins
         * @return 
         * @see #getIdentity()
         */
        public RelyingPartyBuilder origins(@Nonnull final Set<String> origins) {
            this.origins = origins;
            return this;
        }

        /**
         * An abstract database which can look up credentials, usernames and user handles from usernames, user handles and
         * credential IDs. This is a required parameter.
         *
         * <p>
         * This is used to look up:
         * </p>
         *
         * <ul>
         * <li>the user handle for a user logging in via user name</li>
         * <li>the user name for a user logging in via user handle</li>
         * <li>the credential IDs to include in {@link PublicKeyCredentialCreationOptions#getExcludeCredentials()}</li>
         * <li>the credential IDs to include in {@link PublicKeyCredentialRequestOptions#getAllowCredentials()}</li>
         * <li>that the correct user owns the credential when verifying an assertion</li>
         * <li>the public key to use to verify an assertion</li>
         * <li>the stored signature counter when verifying an assertion</li>
         * </ul>
         * @param credentialRepository
         * @return 
         */
        public RelyingPartyBuilder credentialRepository(@Nonnull final CredentialRepository credentialRepository) {
            this.credentialRepository = credentialRepository;
            return this;
        }

        /**
         * The argument for the {@link PublicKeyCredentialCreationOptions#getPubKeyCredParams() pubKeyCredParams} parameter
         * in registration operations.
         *
         * <p>
         * This is a list of acceptable public key algorithms and their parameters, ordered from most to least preferred.
         * </p>
         *
         * <p>
         * The default is the following list:
         * </p>
         *
         * <ol>
         * <li>{@link com.yubico.webauthn.data.PublicKeyCredentialParameters#ES256 ES256}</li>
         * <li>{@link com.yubico.webauthn.data.PublicKeyCredentialParameters#EdDSA EdDSA}</li>
         * <li>{@link com.yubico.webauthn.data.PublicKeyCredentialParameters#RS256 RS256}</li>
         * </ol>
         *
         * @param preferredPubkeyParams
         * @return 
         * @see PublicKeyCredentialCreationOptions#getAttestation()

         * @see <a href="https://www.w3.org/TR/webauthn/#sctn-attestation">§6.4. Attestation</a>
         */
        public RelyingPartyBuilder preferredPubkeyParams(@Nonnull final List<PublicKeyCredentialParameters> preferredPubkeyParams) {
            this.preferredPubkeyParams = preferredPubkeyParams;
            return this;
        }

        /**
         * If <code>true</code>, {@link #finishRegistration(FinishRegistrationOptions) finishRegistration} and {@link
         * #finishAssertion(FinishAssertionOptions) finishAssertion} will accept responses containing extension outputs for
         * which there was no extension input.
         *
         * <p>
         * The default is <code>false</code>.
         * </p>
         *
         * @param allowUnrequestedExtensions
         * @return 
         * @see <a href="https://www.w3.org/TR/webauthn/#extensions">§9. WebAuthn Extensions</a>
         */
        public RelyingPartyBuilder allowUnrequestedExtensions(final boolean allowUnrequestedExtensions) {
            this.allowUnrequestedExtensions = allowUnrequestedExtensions;
            return this;
        }

        /**
         * If <code>false</code>, {@link #finishRegistration(FinishRegistrationOptions) finishRegistration} will only allow
         * registrations where the attestation signature can be linked to a trusted attestation root. This excludes self
         * attestation and none attestation.
         *
         * <p>
         * Regardless of the value of this option, invalid attestation statements of supported formats will always be
         * rejected. For example, a "packed" attestation statement with an invalid signature will be rejected even if this
         * option is set to <code>true</code>.
         * </p>
         *
         * <p>
         * The default is <code>true</code>.
         * </p>
         * @param allowUntrustedAttestation
         * @return 
         */
        public RelyingPartyBuilder allowUntrustedAttestation(final boolean allowUntrustedAttestation) {
            this.allowUntrustedAttestation = allowUntrustedAttestation;
            return this;
        }

        /**
         * If <code>true</code>, {@link #finishAssertion(FinishAssertionOptions) finishAssertion} will fail if the {@link
         * AuthenticatorData#getSignatureCounter() signature counter value} in the response is not strictly greater than the
         * {@link RegisteredCredential#getSignatureCount() stored signature counter value}.
         *
         * <p>
         * The default is <code>true</code>.
         * </p>
         * @param validateSignatureCounter
         * @return 
         */
        public RelyingPartyBuilder validateSignatureCounter(final boolean validateSignatureCounter) {
            this.validateSignatureCounter = validateSignatureCounter;
            return this;
        }

        public RelyingParty build() {
            return new RelyingParty(identity, origins, credentialRepository, appId, attestationConveyancePreference, metadataService, preferredPubkeyParams, allowUnrequestedExtensions, allowUntrustedAttestation, validateSignatureCounter);
        }
    }

    public RelyingPartyBuilder toBuilder() {
        return new RelyingPartyBuilder().identity(this.identity).origins(this.origins).credentialRepository(this.credentialRepository).appId(this.appId).attestationConveyancePreference(this.attestationConveyancePreference).metadataService(this.metadataService).preferredPubkeyParams(this.preferredPubkeyParams).allowUnrequestedExtensions(this.allowUnrequestedExtensions).allowUntrustedAttestation(this.allowUntrustedAttestation).validateSignatureCounter(this.validateSignatureCounter);
    }

    /**
     * The {@link RelyingPartyIdentity} that will be set as the {@link PublicKeyCredentialCreationOptions#getRp() rp}
     * parameter when initiating registration operations, and which {@link AuthenticatorData#getRpIdHash()} will be
     * compared against. This is a required parameter.
     *
     * <p>
     * A successful registration or authentication operation requires {@link AuthenticatorData#getRpIdHash()} to exactly
     * equal the SHA-256 hash of this member's {@link RelyingPartyIdentity#getId() id} member. Alternatively, it may
     * instead equal the SHA-256 hash of {@link #getAppId() appId} if the latter is present.
     * </p>
     *
     * @return 
     * @see #startRegistration(StartRegistrationOptions)
     * @see PublicKeyCredentialCreationOptions
     */
    @Nonnull
    public RelyingPartyIdentity getIdentity() {
        return this.identity;
    }

    /**
     * The allowed origins that returned authenticator responses will be compared against.
     *
     * <p>
     * The default is the set containing only the string <code>"https://" + {@link #getIdentity()}.getId()</code>.
     * </p>
     *
     * <p>
     * A successful registration or authentication operation requires {@link CollectedClientData#getOrigin()} to exactly
     * equal one of these values.
     * </p>
     *
     * @return 
     * @see #getIdentity()
     */
    @Nonnull
    public Set<String> getOrigins() {
        return this.origins;
    }

    /**
     * An abstract database which can look up credentials, usernames and user handles from usernames, user handles and
     * credential IDs. This is a required parameter.
     *
     * <p>
     * This is used to look up:
     * </p>
     *
     * <ul>
     * <li>the user handle for a user logging in via user name</li>
     * <li>the user name for a user logging in via user handle</li>
     * <li>the credential IDs to include in {@link PublicKeyCredentialCreationOptions#getExcludeCredentials()}</li>
     * <li>the credential IDs to include in {@link PublicKeyCredentialRequestOptions#getAllowCredentials()}</li>
     * <li>that the correct user owns the credential when verifying an assertion</li>
     * <li>the public key to use to verify an assertion</li>
     * <li>the stored signature counter when verifying an assertion</li>
     * </ul>
     * @return 
     */
    @Nonnull
    public CredentialRepository getCredentialRepository() {
        return this.credentialRepository;
    }

    /**
     * The extension input to set for the <code>appid</code> extension when initiating authentication operations.
     *
     * <p>
     * If this member is set, {@link #startAssertion(StartAssertionOptions) startAssertion} will automatically set the
     * <code>appid</code> extension input, and {@link #finishAssertion(FinishAssertionOptions) finishAssertion} will
     * adjust its verification logic to also accept this AppID as an alternative to the RP ID.
     * </p>
     *
     * <p>
     * By default, this is not set.
     * </p>
     *
     * @return 
     * @see AssertionExtensionInputs#getAppid()
     * @see <a href="https://www.w3.org/TR/webauthn/#sctn-appid-extension">§10.1. FIDO AppID Extension
     * (appid)</a>
     */
    @Nonnull
    public Optional<AppId> getAppId() {
        return this.appId;
    }

    /**
     * The argument for the {@link PublicKeyCredentialCreationOptions#getAttestation() attestation} parameter in
     * registration operations.
     *
     * <p>
     * Unless your application has a concrete policy for authenticator attestation, it is recommended to leave this
     * parameter undefined.
     * </p>
     *
     * <p>
     * By default, this is not set.
     * </p>
     *
     * @return 
     * @see PublicKeyCredentialCreationOptions#getAttestation()
     * @see <a href="https://www.w3.org/TR/webauthn/#sctn-attestation">§6.4. Attestation</a>
     */
    @Nonnull
    public Optional<AttestationConveyancePreference> getAttestationConveyancePreference() {
        return this.attestationConveyancePreference;
    }

    /**
     * A {@link MetadataService} instance to use for looking up device attestation metadata. This matters only if {@link
     * #getAttestationConveyancePreference()} is non-empty and not set to {@link AttestationConveyancePreference#NONE}.
     *
     * <p>
     * By default, this is not set.
     * </p>
     *
     * @return 
     * @see PublicKeyCredentialCreationOptions#getAttestation()
     * @see <a href="https://www.w3.org/TR/webauthn/#sctn-attestation">§6.4. Attestation</a>
     */
    @Nonnull
    public Optional<MetadataService> getMetadataService() {
        return this.metadataService;
    }

    /**
     * The argument for the {@link PublicKeyCredentialCreationOptions#getPubKeyCredParams() pubKeyCredParams} parameter
     * in registration operations.
     *
     * <p>
     * This is a list of acceptable public key algorithms and their parameters, ordered from most to least preferred.
     * </p>
     *
     * <p>
     * The default is the following list:
     * </p>
     *
     * <ol>
     * <li>{@link com.yubico.webauthn.data.PublicKeyCredentialParameters#ES256 ES256}</li>
     * <li>{@link com.yubico.webauthn.data.PublicKeyCredentialParameters#EdDSA EdDSA}</li>
     * <li>{@link com.yubico.webauthn.data.PublicKeyCredentialParameters#RS256 RS256}</li>
     * </ol>
     *
     * @return 
     * @see PublicKeyCredentialCreationOptions#getAttestation()
     * @see <a href="https://www.w3.org/TR/webauthn/#sctn-attestation">§6.4. Attestation</a>
     */
    @Nonnull
    public List<PublicKeyCredentialParameters> getPreferredPubkeyParams() {
        return this.preferredPubkeyParams;
    }

    /**
     * If <code>true</code>, {@link #finishRegistration(FinishRegistrationOptions) finishRegistration} and {@link
     * #finishAssertion(FinishAssertionOptions) finishAssertion} will accept responses containing extension outputs for
     * which there was no extension input.
     *
     * <p>
     * The default is <code>false</code>.
     * </p>
     *
     * @return 
     * @see <a href="https://www.w3.org/TR/webauthn/#extensions">§9. WebAuthn Extensions</a>
     */
    public boolean isAllowUnrequestedExtensions() {
        return this.allowUnrequestedExtensions;
    }

    /**
     * If <code>false</code>, {@link #finishRegistration(FinishRegistrationOptions) finishRegistration} will only allow
     * registrations where the attestation signature can be linked to a trusted attestation root. This excludes self
     * attestation and none attestation.
     *
     * <p>
     * Regardless of the value of this option, invalid attestation statements of supported formats will always be
     * rejected. For example, a "packed" attestation statement with an invalid signature will be rejected even if this
     * option is set to <code>true</code>.
     * </p>
     *
     * <p>
     * The default is <code>true</code>.
     * </p>
     * @return 
     */
    public boolean isAllowUntrustedAttestation() {
        return this.allowUntrustedAttestation;
    }

    /**
     * If <code>true</code>, {@link #finishAssertion(FinishAssertionOptions) finishAssertion} will fail if the {@link
     * AuthenticatorData#getSignatureCounter() signature counter value} in the response is not strictly greater than the
     * {@link RegisteredCredential#getSignatureCount() stored signature counter value}.
     *
     * <p>
     * The default is <code>true</code>.
     * </p>
     * @return 
     */
    public boolean isValidateSignatureCounter() {
        return this.validateSignatureCounter;
    }
}
