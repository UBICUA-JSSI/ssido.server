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
import ssido.core.attestation.Attestation;
import ssido.core.attestation.MetadataService;
import ssido.core.data.AttestationObject;
import ssido.core.data.AttestationType;
import ssido.core.data.AuthenticatorAttestationResponse;
import ssido.core.data.AuthenticatorSelectionCriteria;
import ssido.core.data.ByteArray;
import ssido.core.data.ClientRegistrationExtensionOutputs;
import ssido.core.data.CollectedClientData;
import ssido.core.data.PublicKeyCredential;
import ssido.core.data.PublicKeyCredentialCreationOptions;
import ssido.core.data.PublicKeyCredentialDescriptor;
import ssido.core.data.UserVerificationRequirement;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import static ssido.util.ExceptionUtil.assure;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class FinishRegistrationSteps {
    private static final Logger LOG = LoggerFactory.getLogger(FinishRegistrationSteps.class);
    
    private static final String CLIENT_DATA_TYPE = "webauthn.create";
    private static final BouncyCastleCrypto crypto = new BouncyCastleCrypto();
    private final PublicKeyCredentialCreationOptions request;
    private final PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> response;
    private final Optional<ByteArray> callerTokenBindingId;
    private final Set<String> origins;
    private final String rpId;
    private final boolean allowUntrustedAttestation;
    private final Optional<MetadataService> metadataService;
    private final CredentialRepository credentialRepository;
    private final boolean allowUnrequestedExtensions;

    public Begin begin() {
        return new Begin();
    }

    public RegistrationResult run() {
        return begin().run();
    }


    interface Step<Next extends Step<?>> {
        Next nextStep();

        void validate();

        List<String> getPrevWarnings();

        default Optional<RegistrationResult> result() {
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

        default Next next() {
            validate();
            return nextStep();
        }

        default RegistrationResult run() {
            if (result().isPresent()) {
                return result().get();
            } else {
                return next().run();
            }
        }
    }

    /**
     * JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON
     */
    final class Begin implements Step<ValidateClientData> {
        @Override
        public void validate() {
        }

        @Override
        public ValidateClientData nextStep() {
            return new ValidateClientData();
        }

        @Override
        public List<String> getPrevWarnings() {
            return Collections.emptyList();
        }

        public Begin() {
        }

       
        @Override
        public String toString() {
            return "FinishRegistrationSteps.Begin()";
        }
    }
    /**
     * The client data claimed as collected during the credential creation, be the result of running an 
     * implementation-specific JSON parser on JSONtext.
     */
    final class ValidateClientData implements Step<ValidateClientDataType> {
        @Override
        public void validate() {
            assure(clientData() != null, "Client data must not be null.");
        }

        @Override
        public ValidateClientDataType nextStep() {
            return new ValidateClientDataType(clientData());
        }

        @Override
        public List<String> getPrevWarnings() {
            return Collections.emptyList();
        }

        public CollectedClientData clientData() {
            return response.getResponse().getClientData();
        }

        public ValidateClientData() {
        }


        @Override
        public String toString() {
            return "FinishRegistrationSteps.ValidateClientData()";
        }
    }

    /**
     * Verify that the value of type is webauthn.create
     */
    final class ValidateClientDataType implements Step<ValidateChallenge> {
        private final CollectedClientData clientData;
        private final List<String> warnings = new ArrayList<>(0);

        @Override
        public void validate() {
            assure(CLIENT_DATA_TYPE.equals(clientData.getType()), "The \"type\" in the client data must be exactly \"%s\", was: %s", CLIENT_DATA_TYPE, clientData.getType());
        }

        @Override
        public ValidateChallenge nextStep() {
            return new ValidateChallenge(clientData, allWarnings());
        }

        @Override
        public List<String> getPrevWarnings() {
            return Collections.emptyList();
        }

        @Override
        public List<String> getWarnings() {
            return CollectionUtil.immutableList(warnings);
        }

        public ValidateClientDataType(final CollectedClientData clientData) {
            this.clientData = clientData;
        }

        public CollectedClientData getClientData() {
            return this.clientData;
        }

        @Override
        public String toString() {
            return "FinishRegistrationSteps.ValidateClientDataType(clientData=" + this.getClientData() + ", warnings=" + this.getWarnings() + ")";
        }
    }

    final class ValidateChallenge implements Step<ValidateOrigin> {
        private final CollectedClientData clientData;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            assure(request.getChallenge().equals(clientData.getChallenge()), "Incorrect challenge.");
        }

        @Override
        public ValidateOrigin nextStep() {
            return new ValidateOrigin(clientData, allWarnings());
        }

        public ValidateChallenge(final CollectedClientData clientData, final List<String> prevWarnings) {
            this.clientData = clientData;
            this.prevWarnings = prevWarnings;
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
            return "FinishRegistrationSteps.ValidateChallenge(clientData=" + this.getClientData() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }


    final class ValidateOrigin implements Step<ValidateTokenBinding> {
        private final CollectedClientData clientData;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            assure(origins.stream().anyMatch(o -> o.equals(clientData.getOrigin())), "Incorrect origin: " + clientData.getOrigin());
        }

        @Override
        public ValidateTokenBinding nextStep() {
            return new ValidateTokenBinding(clientData, allWarnings());
        }

        public ValidateOrigin(final CollectedClientData clientData, final List<String> prevWarnings) {
            this.clientData = clientData;
            this.prevWarnings = prevWarnings;
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
            return "FinishRegistrationSteps.ValidateOrigin(clientData=" + this.getClientData() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }

    final class ValidateTokenBinding implements Step<ValidateClientDataHash> {
        private final CollectedClientData clientData;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            TokenBindingValidator.validate(clientData.getTokenBinding(), callerTokenBindingId);
        }

        @Override
        public ValidateClientDataHash nextStep() {
            return new ValidateClientDataHash(allWarnings());
        }

        public ValidateTokenBinding(final CollectedClientData clientData, final List<String> prevWarnings) {
            this.clientData = clientData;
            this.prevWarnings = prevWarnings;
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
            return "FinishRegistrationSteps.ValidateTokenBinding(clientData=" + this.getClientData() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }

    final class ValidateClientDataHash implements Step<ValidateAttestationObject> {
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            assure(clientDataJsonHash().size() == 32, "Failed to compute hash of client data");
        }

        @Override
        public ValidateAttestationObject nextStep() {
            return new ValidateAttestationObject(clientDataJsonHash(), allWarnings());
        }

        public ByteArray clientDataJsonHash() {
            return crypto.hash(response.getResponse().getClientDataJSON());
        }

        public ValidateClientDataHash(final List<String> prevWarnings) {
            this.prevWarnings = prevWarnings;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishRegistrationSteps.ValidateClientDataHash(prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }


    final class ValidateAttestationObject implements Step<ValidateRpIdHash> {
        private final ByteArray clientDataJsonHash;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            assure(attestation() != null, "Malformed attestation object.");
        }

        @Override
        public ValidateRpIdHash nextStep() {
            return new ValidateRpIdHash(clientDataJsonHash, attestation(), allWarnings());
        }

        public AttestationObject attestation() {
            return response.getResponse().getAttestation();
        }

        public ValidateAttestationObject(final ByteArray clientDataJsonHash, final List<String> prevWarnings) {
            this.clientDataJsonHash = clientDataJsonHash;
            this.prevWarnings = prevWarnings;
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
            return "FinishRegistrationSteps.ValidateAttestationObject(clientDataJsonHash=" + this.getClientDataJsonHash() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }

    final class ValidateRpIdHash implements Step<ValidateUserPresence> {
        private final ByteArray clientDataJsonHash;
        private final AttestationObject attestation;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            assure(crypto.hash(rpId).equals(response.getResponse().getAttestation().getAuthenticatorData().getRpIdHash()), "Wrong RP ID hash.");
        }

        @Override
        public ValidateUserPresence nextStep() {
            return new ValidateUserPresence(clientDataJsonHash, attestation, allWarnings());
        }

        public ValidateRpIdHash(final ByteArray clientDataJsonHash, final AttestationObject attestation, final List<String> prevWarnings) {
            this.clientDataJsonHash = clientDataJsonHash;
            this.attestation = attestation;
            this.prevWarnings = prevWarnings;
        }

        public ByteArray getClientDataJsonHash() {
            return this.clientDataJsonHash;
        }

        public AttestationObject getAttestation() {
            return this.attestation;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishRegistrationSteps.ValidateRpIdHash(clientDataJsonHash=" + this.getClientDataJsonHash() + ", attestation=" + this.getAttestation() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }


    final class ValidateUserPresence implements Step<ValidateUserVerification> {
        private final ByteArray clientDataJsonHash;
        private final AttestationObject attestation;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            assure(response.getResponse().getParsedAuthenticatorData().getFlags().UP, "User Presence is required.");
        }

        @Override
        public ValidateUserVerification nextStep() {
            return new ValidateUserVerification(clientDataJsonHash, attestation, allWarnings());
        }

        public ValidateUserPresence(final ByteArray clientDataJsonHash, final AttestationObject attestation, final List<String> prevWarnings) {
            this.clientDataJsonHash = clientDataJsonHash;
            this.attestation = attestation;
            this.prevWarnings = prevWarnings;
        }

        public ByteArray getClientDataJsonHash() {
            return this.clientDataJsonHash;
        }

        public AttestationObject getAttestation() {
            return this.attestation;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishRegistrationSteps.Step10(clientDataJsonHash=" + this.getClientDataJsonHash() + ", attestation=" + this.getAttestation() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }

    final class ValidateUserVerification implements Step<ValidateExtensions> {
        private final ByteArray clientDataJsonHash;
        private final AttestationObject attestation;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            if (request.getAuthenticatorSelection().map(AuthenticatorSelectionCriteria::getUserVerification).orElse(UserVerificationRequirement.PREFERRED) == UserVerificationRequirement.REQUIRED) {
                assure(response.getResponse().getParsedAuthenticatorData().getFlags().UV, "User Verification is required.");
            }
        }

        @Override
        public ValidateExtensions nextStep() {
            return new ValidateExtensions(clientDataJsonHash, attestation, allWarnings());
        }

        public ValidateUserVerification(final ByteArray clientDataJsonHash, final AttestationObject attestation, final List<String> prevWarnings) {
            this.clientDataJsonHash = clientDataJsonHash;
            this.attestation = attestation;
            this.prevWarnings = prevWarnings;
        }

        public ByteArray getClientDataJsonHash() {
            return this.clientDataJsonHash;
        }

        public AttestationObject getAttestation() {
            return this.attestation;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishRegistrationSteps.ValidateUserVerification(clientDataJsonHash=" + this.getClientDataJsonHash() + ", attestation=" + this.getAttestation() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }


    final class ValidateExtensions implements Step<ValidateAttestationStatementFormat> {
        private final ByteArray clientDataJsonHash;
        private final AttestationObject attestation;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            if (!allowUnrequestedExtensions) {
                ExtensionsValidation.validate(request.getExtensions(), response);
            }
        }

        @Override
        public List<String> getWarnings() {
            try {
                ExtensionsValidation.validate(request.getExtensions(), response);
                return Collections.emptyList();
            } catch (Exception e) {
                return Collections.singletonList(e.getMessage());
            }
        }

        @Override
        public ValidateAttestationStatementFormat nextStep() {
            return new ValidateAttestationStatementFormat(clientDataJsonHash, attestation, allWarnings());
        }

        public ValidateExtensions(final ByteArray clientDataJsonHash, final AttestationObject attestation, final List<String> prevWarnings) {
            this.clientDataJsonHash = clientDataJsonHash;
            this.attestation = attestation;
            this.prevWarnings = prevWarnings;
        }

        public ByteArray getClientDataJsonHash() {
            return this.clientDataJsonHash;
        }

        public AttestationObject getAttestation() {
            return this.attestation;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishRegistrationSteps.ValidateExtensions(clientDataJsonHash=" + this.getClientDataJsonHash() + ", attestation=" + this.getAttestation() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }

    final class ValidateAttestationStatementFormat implements Step<ValidateAttestationSignature> {
        private final ByteArray clientDataJsonHash;
        private final AttestationObject attestation;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
        }

        @Override
        public ValidateAttestationSignature nextStep() {
            return new ValidateAttestationSignature(clientDataJsonHash, attestation, attestationStatementVerifier(), allWarnings());
        }

        public String format() {
            return attestation.getFormat();
        }

        public Optional<AttestationStatementVerifier> attestationStatementVerifier() {
            switch (format()) {
            case "fido-u2f": 
                return Optional.of(new FidoU2fAttestationStatementVerifier());
            case "none": 
                return Optional.of(new NoneAttestationStatementVerifier());
            case "packed": 
                return Optional.of(new PackedAttestationStatementVerifier());
            case "android-safetynet": 
                return Optional.of(new AndroidSafetynetAttestationStatementVerifier());
            default: 
                return Optional.empty();
            }
        }

        public ValidateAttestationStatementFormat(final ByteArray clientDataJsonHash, final AttestationObject attestation, final List<String> prevWarnings) {
            this.clientDataJsonHash = clientDataJsonHash;
            this.attestation = attestation;
            this.prevWarnings = prevWarnings;
        }

        public ByteArray getClientDataJsonHash() {
            return this.clientDataJsonHash;
        }

        public AttestationObject getAttestation() {
            return this.attestation;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishRegistrationSteps.ValidateAttestationStatementFormat(clientDataJsonHash=" + this.getClientDataJsonHash() + ", attestation=" + this.getAttestation() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }

    final class ValidateAttestationSignature implements Step<ValidateTrustAnchor> {
        private final ByteArray clientDataJsonHash;
        private final AttestationObject attestation;
        private final Optional<AttestationStatementVerifier> attestationStatementVerifier;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            attestationStatementVerifier.ifPresent(verifier -> {
                assure(verifier.verifyAttestationSignature(attestation, clientDataJsonHash), "Invalid attestation signature.");
            });
            assure(attestationType() != null, "Failed to determine attestation type");
        }

        @Override
        public ValidateTrustAnchor nextStep() {
            return new ValidateTrustAnchor(attestation, attestationType(), attestationTrustPath(), allWarnings());
        }

        public AttestationType attestationType() {
            try {
                if (attestationStatementVerifier.isPresent()) {
                    return attestationStatementVerifier.get().getAttestationType(attestation);
                } else {
                    switch (attestation.getFormat()) {
                    case "android-key": 
                        // TODO delete this once android-key attestation verification is implemented
                        return AttestationType.BASIC;

                    case "tpm": 
                        // TODO delete this once tpm attestation verification is implemented
                        if (attestation.getAttestationStatement().has("x5c")) {
                            return AttestationType.ATTESTATION_CA;
                        } else {
                            return AttestationType.ECDAA;
                        }

                    default: 
                        throw new IllegalArgumentException("Failed to resolve attestation type; unknown attestation statement format: " + attestation.getFormat());
                    }
                }
            } catch (IOException | CoseException | CertificateException e) {
                throw new IllegalArgumentException("Failed to resolve attestation type.", e);
            }
        }

        public Optional<List<X509Certificate>> attestationTrustPath() {
            if (attestationStatementVerifier.isPresent()) {
                AttestationStatementVerifier verifier = attestationStatementVerifier.get();
                if (verifier instanceof X5cAttestationStatementVerifier) {
                    try {
                        return ((X5cAttestationStatementVerifier) verifier).getAttestationTrustPath(attestation);
                    } catch (CertificateException e) {
                        throw new IllegalArgumentException("Failed to resolve attestation trust path.", e);
                    }
                } else {
                    return Optional.empty();
                }
            } else {
                return Optional.empty();
            }
        }

        public ValidateAttestationSignature(final ByteArray clientDataJsonHash, final AttestationObject attestation, final Optional<AttestationStatementVerifier> attestationStatementVerifier, final List<String> prevWarnings) {
            this.clientDataJsonHash = clientDataJsonHash;
            this.attestation = attestation;
            this.attestationStatementVerifier = attestationStatementVerifier;
            this.prevWarnings = prevWarnings;
        }

        public ByteArray getClientDataJsonHash() {
            return this.clientDataJsonHash;
        }

        public AttestationObject getAttestation() {
            return this.attestation;
        }

        public Optional<AttestationStatementVerifier> getAttestationStatementVerifier() {
            return this.attestationStatementVerifier;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishRegistrationSteps.ValidateAttestationSignature(clientDataJsonHash=" + this.getClientDataJsonHash() + ", attestation=" + this.getAttestation() + ", attestationStatementVerifier=" + this.getAttestationStatementVerifier() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }


    final class ValidateTrustAnchor implements Step<ValidateAttestationTrustAnchor> {
        private final AttestationObject attestation;
        private final AttestationType attestationType;
        private final Optional<List<X509Certificate>> attestationTrustPath;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
        }

        @Override
        public ValidateAttestationTrustAnchor nextStep() {
            return new ValidateAttestationTrustAnchor(attestation, attestationType, attestationTrustPath, trustResolver(), allWarnings());
        }

        public Optional<AttestationTrustResolver> trustResolver() {
            switch (attestationType) {
            case SELF_ATTESTATION: 
                return Optional.empty();
            case ATTESTATION_CA: 
            case BASIC: 
                switch (attestation.getFormat()) {
                case "android-key": 
                case "android-safetynet": 
                case "fido-u2f": 
                case "packed": 
                case "tpm": 
                    return metadataService.map(KnownX509TrustAnchorsTrustResolver::new);
                default: 
                    throw new UnsupportedOperationException(String.format("Attestation type %s is not supported for attestation statement format \"%s\".", attestationType, attestation.getFormat()));
                }

            case NONE: 
                return Optional.empty();
            default: 
                throw new UnsupportedOperationException("Attestation type not implemented: " + attestationType);
            }
        }

        public ValidateTrustAnchor(final AttestationObject attestation, final AttestationType attestationType, final Optional<List<X509Certificate>> attestationTrustPath, final List<String> prevWarnings) {
            this.attestation = attestation;
            this.attestationType = attestationType;
            this.attestationTrustPath = attestationTrustPath;
            this.prevWarnings = prevWarnings;
        }

        public AttestationObject getAttestation() {
            return this.attestation;
        }

        public AttestationType getAttestationType() {
            return this.attestationType;
        }

        public Optional<List<X509Certificate>> getAttestationTrustPath() {
            return this.attestationTrustPath;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishRegistrationSteps.ValidateTrustAnchor(attestation=" + this.getAttestation() + ", attestationType=" + this.getAttestationType() + ", attestationTrustPath=" + this.getAttestationTrustPath() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }

    final class ValidateAttestationTrustAnchor implements Step<ValidateCredentialRegistered> {
        private final AttestationObject attestation;
        private final AttestationType attestationType;
        private final Optional<List<X509Certificate>> attestationTrustPath;
        private final Optional<AttestationTrustResolver> trustResolver;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            assure(trustResolver.isPresent() || allowUntrustedAttestation, "Failed to obtain attestation trust anchors.");
            switch (attestationType) {
            case SELF_ATTESTATION: 
                assure(allowUntrustedAttestation, "Self attestation is not allowed.");
                break;
            case ATTESTATION_CA: 
            case BASIC: 
                assure(allowUntrustedAttestation || attestationTrusted(), "Failed to derive trust for attestation key.");
                break;
            case NONE: 
                assure(allowUntrustedAttestation, "No attestation is not allowed.");
                break;
            default: 
                throw new UnsupportedOperationException("Attestation type not implemented: " + attestationType);
            }
        }

        @Override
        public ValidateCredentialRegistered nextStep() {
            return new ValidateCredentialRegistered(attestationType, attestationMetadata(), attestationTrusted(), allWarnings());
        }

        public boolean attestationTrusted() {
            switch (attestationType) {
            case SELF_ATTESTATION: 
            case NONE: 
                return false;
            case ATTESTATION_CA: 
            case BASIC: 
                return attestationMetadata().filter(Attestation::isTrusted).isPresent();
            default: 
                throw new UnsupportedOperationException("Attestation type not implemented: " + attestationType);
            }
        }

        public Optional<Attestation> attestationMetadata() {
            return trustResolver.flatMap(tr -> {
                try {
                    return Optional.of(tr.resolveTrustAnchor(attestationTrustPath.orElseGet(Collections::emptyList)));
                } catch (CertificateEncodingException e) {
                    LOG.debug("Failed to resolve trust anchor for attestation: {}", attestation, e);
                    return Optional.empty();
                }
            });
        }

        @Override
        public List<String> getWarnings() {
            return trustResolver.map(tr -> {
                try {
                    tr.resolveTrustAnchor(attestationTrustPath.orElseGet(Collections::emptyList));
                    return Collections.<String>emptyList();
                } catch (CertificateEncodingException e) {
                    return Collections.singletonList("Failed to resolve trust anchor: " + e);
                }
            }).orElseGet(Collections::emptyList);
        }

        public ValidateAttestationTrustAnchor(final AttestationObject attestation, final AttestationType attestationType, final Optional<List<X509Certificate>> attestationTrustPath, final Optional<AttestationTrustResolver> trustResolver, final List<String> prevWarnings) {
            this.attestation = attestation;
            this.attestationType = attestationType;
            this.attestationTrustPath = attestationTrustPath;
            this.trustResolver = trustResolver;
            this.prevWarnings = prevWarnings;
        }

        public AttestationObject getAttestation() {
            return this.attestation;
        }

        public AttestationType getAttestationType() {
            return this.attestationType;
        }

        public Optional<List<X509Certificate>> getAttestationTrustPath() {
            return this.attestationTrustPath;
        }

        public Optional<AttestationTrustResolver> getTrustResolver() {
            return this.trustResolver;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishRegistrationSteps.ValidateAttestationTrustAnchor(attestation=" + this.getAttestation() + ", attestationType=" + this.getAttestationType() + ", attestationTrustPath=" + this.getAttestationTrustPath() + ", trustResolver=" + this.getTrustResolver() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }

    final class ValidateCredentialRegistered implements Step<Step18> {
        private final AttestationType attestationType;
        private final Optional<Attestation> attestationMetadata;
        private final boolean attestationTrusted;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            assure(credentialRepository.lookupAll(response.getId()).isEmpty(), "Credential ID is already registered: %s", response.getId());
        }

        @Override
        public Step18 nextStep() {
            return new Step18(attestationType, attestationMetadata, attestationTrusted, allWarnings());
        }

        public ValidateCredentialRegistered(final AttestationType attestationType, final Optional<Attestation> attestationMetadata, final boolean attestationTrusted, final List<String> prevWarnings) {
            this.attestationType = attestationType;
            this.attestationMetadata = attestationMetadata;
            this.attestationTrusted = attestationTrusted;
            this.prevWarnings = prevWarnings;
        }

        public AttestationType getAttestationType() {
            return this.attestationType;
        }

        public Optional<Attestation> getAttestationMetadata() {
            return this.attestationMetadata;
        }

        public boolean isAttestationTrusted() {
            return this.attestationTrusted;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishRegistrationSteps.ValidateCredentialRegistered(attestationType=" + this.getAttestationType() + ", attestationMetadata=" + this.getAttestationMetadata() + ", attestationTrusted=" + this.isAttestationTrusted() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }


    final class Step18 implements Step<Step19> {
        private final AttestationType attestationType;
        private final Optional<Attestation> attestationMetadata;
        private final boolean attestationTrusted;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
        }

        @Override
        public Step19 nextStep() {
            return new Step19(attestationType, attestationMetadata, attestationTrusted, allWarnings());
        }

        public Step18(final AttestationType attestationType, final Optional<Attestation> attestationMetadata, final boolean attestationTrusted, final List<String> prevWarnings) {
            this.attestationType = attestationType;
            this.attestationMetadata = attestationMetadata;
            this.attestationTrusted = attestationTrusted;
            this.prevWarnings = prevWarnings;
        }

        public AttestationType getAttestationType() {
            return this.attestationType;
        }

        public Optional<Attestation> getAttestationMetadata() {
            return this.attestationMetadata;
        }

        public boolean isAttestationTrusted() {
            return this.attestationTrusted;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishRegistrationSteps.Step18(attestationType=" + this.getAttestationType() + ", attestationMetadata=" + this.getAttestationMetadata() + ", attestationTrusted=" + this.isAttestationTrusted() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }


    final class Step19 implements Step<Finished> {
        private final AttestationType attestationType;
        private final Optional<Attestation> attestationMetadata;
        private final boolean attestationTrusted;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
        }

        @Override
        public Finished nextStep() {
            return new Finished(attestationType, attestationMetadata, attestationTrusted, allWarnings());
        }

        public Step19(final AttestationType attestationType, final Optional<Attestation> attestationMetadata, final boolean attestationTrusted, final List<String> prevWarnings) {
            this.attestationType = attestationType;
            this.attestationMetadata = attestationMetadata;
            this.attestationTrusted = attestationTrusted;
            this.prevWarnings = prevWarnings;
        }

        public AttestationType getAttestationType() {
            return this.attestationType;
        }

        public Optional<Attestation> getAttestationMetadata() {
            return this.attestationMetadata;
        }

        public boolean isAttestationTrusted() {
            return this.attestationTrusted;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }

        @Override
        public String toString() {
            return "FinishRegistrationSteps.Step19(attestationType=" + this.getAttestationType() + ", attestationMetadata=" + this.getAttestationMetadata() + ", attestationTrusted=" + this.isAttestationTrusted() + ", prevWarnings=" + this.getPrevWarnings() + ")";
        }
    }


    final class Finished implements Step<Finished> {
        private final AttestationType attestationType;
        private final Optional<Attestation> attestationMetadata;
        private final boolean attestationTrusted;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            /* No-op */ }

        @Override
        public Finished nextStep() {
            return this;
        }

        @Override
        public Optional<RegistrationResult> result() {
            return Optional.of(RegistrationResult.builder().keyId(keyId()).attestationTrusted(attestationTrusted).attestationType(attestationType).publicKeyCose(response.getResponse().getAttestation().getAuthenticatorData().getAttestedCredentialData().get().getCredentialPublicKey()).attestationMetadata(attestationMetadata).warnings(allWarnings()).build());
        }

        private PublicKeyCredentialDescriptor keyId() {
            return PublicKeyCredentialDescriptor.builder().id(response.getId()).type(response.getType()).build();
        }

        public Finished(final AttestationType attestationType, final Optional<Attestation> attestationMetadata, final boolean attestationTrusted, final List<String> prevWarnings) {
            this.attestationType = attestationType;
            this.attestationMetadata = attestationMetadata;
            this.attestationTrusted = attestationTrusted;
            this.prevWarnings = prevWarnings;
        }

        public AttestationType getAttestationType() {
            return this.attestationType;
        }

        public Optional<Attestation> getAttestationMetadata() {
            return this.attestationMetadata;
        }

        public boolean isAttestationTrusted() {
            return this.attestationTrusted;
        }

        @Override
        public List<String> getPrevWarnings() {
            return this.prevWarnings;
        }
    }

    FinishRegistrationSteps(final PublicKeyCredentialCreationOptions request, final PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> response, final Optional<ByteArray> callerTokenBindingId, final Set<String> origins, final String rpId, final boolean allowUntrustedAttestation, final Optional<MetadataService> metadataService, final CredentialRepository credentialRepository, final boolean allowUnrequestedExtensions) {
        this.request = request;
        this.response = response;
        this.callerTokenBindingId = callerTokenBindingId;
        this.origins = origins;
        this.rpId = rpId;
        this.allowUntrustedAttestation = allowUntrustedAttestation;
        this.metadataService = metadataService;
        this.credentialRepository = credentialRepository;
        this.allowUnrequestedExtensions = allowUnrequestedExtensions;
    }


    public static class FinishRegistrationStepsBuilder {
        private PublicKeyCredentialCreationOptions request;
        private PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> response;
        private Optional<ByteArray> callerTokenBindingId;
        private Set<String> origins;
        private String rpId;
        private boolean allowUntrustedAttestation;
        private Optional<MetadataService> metadataService;
        private CredentialRepository credentialRepository;
        private boolean allowUnrequestedExtensions = false;

        FinishRegistrationStepsBuilder() {
        }

        public FinishRegistrationStepsBuilder request(final PublicKeyCredentialCreationOptions request) {
            this.request = request;
            return this;
        }

        public FinishRegistrationStepsBuilder response(final PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> response) {
            this.response = response;
            return this;
        }

        @java.lang.SuppressWarnings("all")
        public FinishRegistrationStepsBuilder callerTokenBindingId(final Optional<ByteArray> callerTokenBindingId) {
            this.callerTokenBindingId = callerTokenBindingId;
            return this;
        }

        public FinishRegistrationStepsBuilder origins(final Set<String> origins) {
            this.origins = origins;
            return this;
        }

        public FinishRegistrationStepsBuilder rpId(final String rpId) {
            this.rpId = rpId;
            return this;
        }

        public FinishRegistrationStepsBuilder allowUntrustedAttestation(final boolean allowUntrustedAttestation) {
            this.allowUntrustedAttestation = allowUntrustedAttestation;
            return this;
        }

        public FinishRegistrationStepsBuilder metadataService(final Optional<MetadataService> metadataService) {
            this.metadataService = metadataService;
            return this;
        }

        public FinishRegistrationStepsBuilder credentialRepository(final CredentialRepository credentialRepository) {
            this.credentialRepository = credentialRepository;
            return this;
        }

        public FinishRegistrationStepsBuilder allowUnrequestedExtensions(final boolean allowUnrequestedExtensions) {
            this.allowUnrequestedExtensions = allowUnrequestedExtensions;
            return this;
        }

        public FinishRegistrationSteps build() {
            return new FinishRegistrationSteps(request, response, callerTokenBindingId, origins, rpId, allowUntrustedAttestation, metadataService, credentialRepository, allowUnrequestedExtensions);
        }
    }

    public static FinishRegistrationStepsBuilder builder() {
        return new FinishRegistrationStepsBuilder();
    }
}
