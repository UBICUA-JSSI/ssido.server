package ssido.data;

import ssido.core.attestation.Attestation;
import ssido.core.data.ByteArray;
import ssido.core.data.PublicKeyCredentialDescriptor;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;

public final class U2fRegistrationResult {
    @Nonnull
    private final PublicKeyCredentialDescriptor keyId;
    private final boolean attestationTrusted;
    @Nonnull
    private final ByteArray publicKeyCose;
    @Nonnull
    private final List<String> warnings;
    @Nonnull
    private final Optional<Attestation> attestationMetadata;

    U2fRegistrationResult(@Nonnull final PublicKeyCredentialDescriptor keyId, final boolean attestationTrusted, @Nonnull final ByteArray publicKeyCose, @Nonnull final List<String> warnings, @Nonnull final Optional<Attestation> attestationMetadata) {
        this.keyId = keyId;
        this.attestationTrusted = attestationTrusted;
        this.publicKeyCose = publicKeyCose;
        this.warnings = warnings;
        this.attestationMetadata = attestationMetadata;
    }


    public static class U2fRegistrationResultBuilder {
        private PublicKeyCredentialDescriptor keyId;
        private boolean attestationTrusted;
        private ByteArray publicKeyCose;
        private List<String> warnings = Collections.emptyList();
        private Optional<Attestation> attestationMetadata = Optional.empty();

        U2fRegistrationResultBuilder() {
        }

        public U2fRegistrationResultBuilder keyId(@Nonnull final PublicKeyCredentialDescriptor keyId) {
            this.keyId = keyId;
            return this;
        }

        public U2fRegistrationResultBuilder attestationTrusted(final boolean attestationTrusted) {
            this.attestationTrusted = attestationTrusted;
            return this;
        }

        public U2fRegistrationResultBuilder publicKeyCose(@Nonnull final ByteArray publicKeyCose) {
            this.publicKeyCose = publicKeyCose;
            return this;
        }

        public U2fRegistrationResultBuilder warnings(@Nonnull final List<String> warnings) {
            this.warnings = warnings;
            return this;
        }

        public U2fRegistrationResultBuilder attestationMetadata(@Nonnull final Optional<Attestation> attestationMetadata) {
            this.attestationMetadata = attestationMetadata;
            return this;
        }

        public U2fRegistrationResult build() {
            return new U2fRegistrationResult(keyId, attestationTrusted, publicKeyCose, warnings, attestationMetadata);
        }

        @Override
        public String toString() {
            return "U2fRegistrationResult.U2fRegistrationResultBuilder(keyId=" + this.keyId + ", attestationTrusted=" + this.attestationTrusted + ", publicKeyCose=" + this.publicKeyCose + ", warnings=" + this.warnings + ", attestationMetadata=" + this.attestationMetadata + ")";
        }
    }

    public static U2fRegistrationResultBuilder builder() {
        return new U2fRegistrationResultBuilder();
    }

    @Nonnull
    public PublicKeyCredentialDescriptor getKeyId() {
        return this.keyId;
    }

    public boolean isAttestationTrusted() {
        return this.attestationTrusted;
    }

    @Nonnull
    public ByteArray getPublicKeyCose() {
        return this.publicKeyCose;
    }

    @Nonnull
    public List<String> getWarnings() {
        return this.warnings;
    }

    @Nonnull
    public Optional<Attestation> getAttestationMetadata() {
        return this.attestationMetadata;
    }
}
