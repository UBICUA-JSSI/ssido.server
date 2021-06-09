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
import ssido.core.attestation.Attestation;
import ssido.core.data.AttestationType;
import ssido.core.data.ByteArray;
import ssido.core.data.PublicKeyCredential;
import ssido.core.data.PublicKeyCredentialDescriptor;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * The result of a call to {@link RelyingParty#finishRegistration(FinishRegistrationOptions)}.
 */
public final class RegistrationResult {
    /**
     * The <a href="https://www.w3.org/TR/webauthn/#credential-id">credential ID</a> of the created
     * credential.
     *
     * @see <a href="https://www.w3.org/TR/webauthn/#credential-id">Credential ID</a>
     * @see PublicKeyCredential#getId()
     */
    @Nonnull
    private final PublicKeyCredentialDescriptor keyId;
    /**
     * <code>true</code> if and only if the attestation signature was successfully linked to a trusted attestation
     * root.
     *
     * <p>
     * You can ignore this if authenticator attestation is not relevant to your application.
     * </p>
     */
    private final boolean attestationTrusted;
    /**
     * The attestation type <a href="https://www.w3.org/TR/webauthn/#sctn-attestation-types">§6.4.3.
     * Attestation Types</a> that was used for the created credential.
     *
     * <p>
     * You can ignore this if authenticator attestation is not relevant to your application.
     * </p>
     *
     * @see <a href="https://www.w3.org/TR/webauthn/#sctn-attestation-types">§6.4.3. Attestation
     * Types</a>
     */
    @Nonnull
    private final AttestationType attestationType;
    /**
     * The public key of the created credential.
     *
     * <p>
     * This is used in {@link RelyingParty#finishAssertion(FinishAssertionOptions)} to verify the authentication
     * signatures.
     * </p>
     *
     * @see RegisteredCredential#getPublicKeyCose()
     */
    @Nonnull
    private final ByteArray publicKeyCose;
    /**
     * Zero or more human-readable messages about non-critical issues.
     */
    @Nonnull
    private final List<String> warnings;
    /**
     * Additional information about the authenticator, identified based on the attestation certificate.
     *
     * <p>
     * This will be absent unless you set a {@link com.yubico.webauthn.RelyingParty.RelyingPartyBuilder#metadataService(Optional)
     * metadataService} in {@link RelyingParty}.
     * </p>
     *
     * @see <a href="https://www.w3.org/TR/webauthn/#sctn-attestation">§6.4. Attestation</a>
     * @see com.yubico.webauthn.RelyingParty.RelyingPartyBuilder#metadataService(Optional)
     */
    @Nonnull
    private final Optional<Attestation> attestationMetadata;

    @JsonCreator
    private RegistrationResult(@Nonnull @JsonProperty("keyId") PublicKeyCredentialDescriptor keyId, @JsonProperty("attestationTrusted") boolean attestationTrusted, @Nonnull @JsonProperty("attestationType") AttestationType attestationType, @Nonnull @JsonProperty("publicKeyCose") ByteArray publicKeyCose, @Nonnull @JsonProperty("warnings") List<String> warnings, @Nonnull @JsonProperty("attestationMetadata") Optional<Attestation> attestationMetadata) {
        this.keyId = keyId;
        this.attestationTrusted = attestationTrusted;
        this.attestationType = attestationType;
        this.publicKeyCose = publicKeyCose;
        this.warnings = CollectionUtil.immutableList(warnings);
        this.attestationMetadata = attestationMetadata;
    }

    static RegistrationResultBuilder.MandatoryStages builder() {
        return new RegistrationResultBuilder.MandatoryStages();
    }


    static class RegistrationResultBuilder {
        private PublicKeyCredentialDescriptor keyId;
        private boolean attestationTrusted;
        private AttestationType attestationType;
        private ByteArray publicKeyCose;
        private List<String> warnings = Collections.emptyList();
        private Optional<Attestation> attestationMetadata = Optional.empty();


        public static class MandatoryStages {
            private final RegistrationResultBuilder builder = new RegistrationResultBuilder();

            public Step2 keyId(PublicKeyCredentialDescriptor keyId) {
                builder.keyId(keyId);
                return new Step2();
            }


            public class Step2 {
                public Step3 attestationTrusted(boolean attestationTrusted) {
                    builder.attestationTrusted(attestationTrusted);
                    return new Step3();
                }
            }


            public class Step3 {
                public Step4 attestationType(AttestationType attestationType) {
                    builder.attestationType(attestationType);
                    return new Step4();
                }
            }


            public class Step4 {
                public RegistrationResultBuilder publicKeyCose(ByteArray publicKeyCose) {
                    return builder.publicKeyCose(publicKeyCose);
                }
            }
        }

        RegistrationResultBuilder() {
        }

        /**
         * The <a href="https://www.w3.org/TR/webauthn/#credential-id">credential ID</a> of the created
         * credential.
         *
         * @see <a href="https://www.w3.org/TR/webauthn/#credential-id">Credential ID</a>
         * @see PublicKeyCredential#getId()
         */
        public RegistrationResultBuilder keyId(@Nonnull final PublicKeyCredentialDescriptor keyId) {
            this.keyId = keyId;
            return this;
        }

        /**
         * <code>true</code> if and only if the attestation signature was successfully linked to a trusted attestation
         * root.
         *
         * <p>
         * You can ignore this if authenticator attestation is not relevant to your application.
         * </p>
         */
        public RegistrationResultBuilder attestationTrusted(final boolean attestationTrusted) {
            this.attestationTrusted = attestationTrusted;
            return this;
        }

        /**
         * The attestation type <a href="https://www.w3.org/TR/webauthn/#sctn-attestation-types">§6.4.3.
         * Attestation Types</a> that was used for the created credential.
         *
         * <p>
         * You can ignore this if authenticator attestation is not relevant to your application.
         * </p>
         *
         * @see <a href="https://www.w3.org/TR/webauthn/#sctn-attestation-types">§6.4.3. Attestation
         * Types</a>
         */
        public RegistrationResultBuilder attestationType(@Nonnull final AttestationType attestationType) {
            this.attestationType = attestationType;
            return this;
        }

        /**
         * The public key of the created credential.
         *
         * <p>
         * This is used in {@link RelyingParty#finishAssertion(FinishAssertionOptions)} to verify the authentication
         * signatures.
         * </p>
         *
         * @see RegisteredCredential#getPublicKeyCose()
         */
        @java.lang.SuppressWarnings("all")
        public RegistrationResultBuilder publicKeyCose(@Nonnull final ByteArray publicKeyCose) {
            this.publicKeyCose = publicKeyCose;
            return this;
        }

        /**
         * Zero or more human-readable messages about non-critical issues.
         */
        public RegistrationResultBuilder warnings(@Nonnull final List<String> warnings) {
            this.warnings = warnings;
            return this;
        }

        /**
         * Additional information about the authenticator, identified based on the attestation certificate.
         *
         * <p>
         * This will be absent unless you set a {@link com.yubico.webauthn.RelyingParty.RelyingPartyBuilder#metadataService(Optional)
         * metadataService} in {@link RelyingParty}.
         * </p>
         *
         * @see <a href="https://www.w3.org/TR/webauthn/#sctn-attestation">§6.4. Attestation</a>
         * @see com.yubico.webauthn.RelyingParty.RelyingPartyBuilder#metadataService(Optional)
         */
        public RegistrationResultBuilder attestationMetadata(@Nonnull final Optional<Attestation> attestationMetadata) {
            this.attestationMetadata = attestationMetadata;
            return this;
        }

        public RegistrationResult build() {
            return new RegistrationResult(keyId, attestationTrusted, attestationType, publicKeyCose, warnings, attestationMetadata);
        }

    }

    public RegistrationResultBuilder toBuilder() {
        return new RegistrationResultBuilder().keyId(this.keyId).attestationTrusted(this.attestationTrusted).attestationType(this.attestationType).publicKeyCose(this.publicKeyCose).warnings(this.warnings).attestationMetadata(this.attestationMetadata);
    }

    /**
     * The <a href="https://www.w3.org/TR/webauthn/#credential-id">credential ID</a> of the created
     * credential.
     *
     * @return 
     * @see <a href="https://www.w3.org/TR/webauthn/#credential-id">Credential ID</a>
     * @see PublicKeyCredential#getId()
     */
    @Nonnull
    public PublicKeyCredentialDescriptor getKeyId() {
        return this.keyId;
    }

    /**
     * <code>true</code> if and only if the attestation signature was successfully linked to a trusted attestation
     * root.
     *
     * <p>
     * You can ignore this if authenticator attestation is not relevant to your application.
     * </p>
     */
    public boolean isAttestationTrusted() {
        return this.attestationTrusted;
    }

    /**
     * The attestation type <a href="https://www.w3.org/TR/webauthn/#sctn-attestation-types">§6.4.3.
     * Attestation Types</a> that was used for the created credential.
     *
     * <p>
     * You can ignore this if authenticator attestation is not relevant to your application.
     * </p>
     *
     * @return 
     * @see <a href="https://www.w3.org/TR/webauthn/#sctn-attestation-types">§6.4.3. Attestation
     * Types</a>
     */
    @Nonnull
    public AttestationType getAttestationType() {
        return this.attestationType;
    }

    /**
     * The public key of the created credential.
     *
     * <p>
     * This is used in {@link RelyingParty#finishAssertion(FinishAssertionOptions)} to verify the authentication
     * signatures.
     * </p>
     *
     * @return 
     * @see RegisteredCredential#getPublicKeyCose()
     */
    @Nonnull
    public ByteArray getPublicKeyCose() {
        return this.publicKeyCose;
    }

    /**
     * Zero or more human-readable messages about non-critical issues.
     * @return 
     */
    @Nonnull
    public List<String> getWarnings() {
        return this.warnings;
    }

    /**
     * Additional information about the authenticator, identified based on the attestation certificate.
     *
     * <p>
     * This will be absent unless you set a {@link com.yubico.webauthn.RelyingParty.RelyingPartyBuilder#metadataService(Optional)
     * metadataService} in {@link RelyingParty}.
     * </p>
     *
     * @return 
     * @see <a href="https://www.w3.org/TR/webauthn/#sctn-attestation">§6.4. Attestation</a>
     * @see com.yubico.webauthn.RelyingParty.RelyingPartyBuilder#metadataService(Optional)
     */
    @Nonnull
    public Optional<Attestation> getAttestationMetadata() {
        return this.attestationMetadata;
    }
}
