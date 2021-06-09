// Copyright (c) 2015-2018, Yubico AB
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
package ssido.core.attestation;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import javax.annotation.Nonnull;

/**
 * Non-standardized representation of partly free-form information about an authenticator device.
 */
public final class Attestation implements Serializable {
    /**
     * <code>true</code> if and only if the contained information has been verified to be cryptographically supported by
     * a trusted attestation root.
     */
    private final boolean trusted;
    /**
     * A unique identifier for a particular version of the data source of the data in this object.
     */
    @Nonnull
    private final Optional<String> metadataIdentifier;
    /**
     * Free-form information about the authenticator vendor.
     */
    @Nonnull
    private final Optional<Map<String, String>> vendorProperties;
    /**
     * Free-form information about the authenticator model.
     */
    @Nonnull
    private final Optional<Map<String, String>> deviceProperties;
    /**
     * The set of communication modes supported by the authenticator.
     */
    @Nonnull
    private final Optional<Set<Transport>> transports;

    @JsonCreator
    private Attestation(@JsonProperty("trusted") boolean trusted, @Nonnull @JsonProperty("metadataIdentifier") Optional<String> metadataIdentifier, @Nonnull @JsonProperty("vendorProperties") Optional<Map<String, String>> vendorProperties, @Nonnull @JsonProperty("deviceProperties") Optional<Map<String, String>> deviceProperties, @Nonnull @JsonProperty("transports") Optional<Set<Transport>> transports) {
        this.trusted = trusted;
        this.metadataIdentifier = metadataIdentifier;
        this.vendorProperties = vendorProperties;
        this.deviceProperties = deviceProperties;
        this.transports = transports.map(TreeSet::new);
    }

    public static Attestation empty() {
        return builder().trusted(false).build();
    }

    public static AttestationBuilder.MandatoryStages builder() {
        return new AttestationBuilder.MandatoryStages();
    }


    public static class AttestationBuilder {
        private boolean trusted;
        private Optional<String> metadataIdentifier = Optional.empty();
        private Optional<Map<String, String>> vendorProperties = Optional.empty();
        private Optional<Map<String, String>> deviceProperties = Optional.empty();
        private Optional<Set<Transport>> transports = Optional.empty();


        public static class MandatoryStages {
            private final AttestationBuilder builder = new AttestationBuilder();

            public AttestationBuilder trusted(boolean trusted) {
                return builder.trusted(trusted);
            }
        }

        AttestationBuilder() {
        }

        /**
         * <code>true</code> if and only if the contained information has been verified to be cryptographically supported by

         * a trusted attestation root.
         * @param trusted
         * @return 
         */
        public AttestationBuilder trusted(final boolean trusted) {
            this.trusted = trusted;
            return this;
        }

        /**
         * A unique identifier for a particular version of the data source of the data in this object.
         * @param metadataIdentifier
         * @return 
         */
        public AttestationBuilder metadataIdentifier(@Nonnull final Optional<String> metadataIdentifier) {
            this.metadataIdentifier = metadataIdentifier;
            return this;
        }

        /**
         * Free-form information about the authenticator vendor.
         * @param vendorProperties
         * @return 
         */
        public AttestationBuilder vendorProperties(@Nonnull final Optional<Map<String, String>> vendorProperties) {
            this.vendorProperties = vendorProperties;
            return this;
        }

        /**
         * Free-form information about the authenticator model.
         * @param deviceProperties
         * @return 
         */
        public AttestationBuilder deviceProperties(@Nonnull final Optional<Map<String, String>> deviceProperties) {
            this.deviceProperties = deviceProperties;
            return this;
        }

        /**
         * The set of communication modes supported by the authenticator.
         * @param transports
         * @return 
         */
        public AttestationBuilder transports(@Nonnull final Optional<Set<Transport>> transports) {
            this.transports = transports;
            return this;
        }

        public Attestation build() {
            return new Attestation(trusted, metadataIdentifier, vendorProperties, deviceProperties, transports);
        }
    }
   
    public AttestationBuilder toBuilder() {
        return new AttestationBuilder().trusted(this.trusted).metadataIdentifier(this.metadataIdentifier).vendorProperties(this.vendorProperties).deviceProperties(this.deviceProperties).transports(this.transports);
    }

    /**
     * <code>true</code> if and only if the contained information has been verified to be cryptographically supported by
     * a trusted attestation root.
     * @return 
     */
    public boolean isTrusted() {
        return this.trusted;
    }

    /**
     * A unique identifier for a particular version of the data source of the data in this object.
     * @return 
     */
    @Nonnull
    public Optional<String> getMetadataIdentifier() {
        return this.metadataIdentifier;
    }

    /**
     * Free-form information about the authenticator vendor.
     * @return 
     */
    @Nonnull
    public Optional<Map<String, String>> getVendorProperties() {
        return this.vendorProperties;
    }

    /**
     * Free-form information about the authenticator model.
     * @return 
     */
    @Nonnull
    public Optional<Map<String, String>> getDeviceProperties() {
        return this.deviceProperties;
    }

    /**
     * The set of communication modes supported by the authenticator.
     * @return 
     */
    @Nonnull
    public Optional<Set<Transport>> getTransports() {
        return this.transports;
    }
}
