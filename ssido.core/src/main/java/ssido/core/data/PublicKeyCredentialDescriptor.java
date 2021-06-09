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
package ssido.core.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import ssido.util.CollectionUtil;
import ssido.util.EnumUtil;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import javax.annotation.Nonnull;

/**
 * The attributes that are specified by a caller when referring to a public key credential as an input parameter to the
 * <code>navigator.credentials.create()</code> or <code>navigator.credentials.get()</code> methods. It mirrors the
 * fields of the {@link PublicKeyCredential} object returned by the latter methods.
 *
 * @see <a href="https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor">§5.10.3.
 * Credential Descriptor (dictionary PublicKeyCredentialDescriptor)</a>
 */
public final class PublicKeyCredentialDescriptor implements Comparable<PublicKeyCredentialDescriptor> {
    /**
     * The type of the credential the caller is referring to.
     */
    @Nonnull
    private final PublicKeyCredentialType type;
    /**
     * The credential ID of the public key credential the caller is referring to.
     */
    @Nonnull
    private final ByteArray id;
    /**
     * An OPTIONAL hint as to how the client might communicate with the managing authenticator of the public key
     * credential the caller is referring to.
     */
    @Nonnull
    private final Optional<Set<AuthenticatorTransport>> transports;

    private PublicKeyCredentialDescriptor(@Nonnull PublicKeyCredentialType type, @Nonnull ByteArray id, @Nonnull Optional<Set<AuthenticatorTransport>> transports) {
        this.type = type;
        this.id = id;
        this.transports = transports.map(TreeSet::new).map(CollectionUtil::immutableSortedSet);
    }

    @JsonCreator
    private PublicKeyCredentialDescriptor(@Nonnull @JsonProperty("type") PublicKeyCredentialType type, @Nonnull @JsonProperty("id") ByteArray id, @JsonProperty("transports") Set<AuthenticatorTransport> transports) {
        this(type, id, Optional.ofNullable(transports));
    }

    @Override
    public int compareTo(PublicKeyCredentialDescriptor other) {
        int idComparison = id.compareTo(other.id);
        if (idComparison != 0) {
            return idComparison;
        }
        if (type.compareTo(other.type) != 0) {
            return type.compareTo(other.type);
        }
        if (!transports.isPresent() && other.transports.isPresent()) {
            return -1;
        } else if (transports.isPresent() && !other.transports.isPresent()) {
            return 1;
        } else if (transports.isPresent() && other.transports.isPresent()) {
            int transportsComparison = EnumUtil.compareSets(transports.get(), other.transports.get(), AuthenticatorTransport.class);
            if (transportsComparison != 0) {
                return transportsComparison;
            }
        }
        return 0;
    }

    public static PublicKeyCredentialDescriptorBuilder.MandatoryStages builder() {
        return new PublicKeyCredentialDescriptorBuilder.MandatoryStages();
    }


    public static class PublicKeyCredentialDescriptorBuilder {
        private PublicKeyCredentialType type = PublicKeyCredentialType.PUBLIC_KEY;
        private ByteArray id;
        private Optional<Set<AuthenticatorTransport>> transports = Optional.empty();


        public static class MandatoryStages {
            private final PublicKeyCredentialDescriptorBuilder builder = new PublicKeyCredentialDescriptorBuilder();

            public PublicKeyCredentialDescriptorBuilder id(ByteArray id) {
                return builder.id(id);
            }
        }

        /**
         * An OPTIONAL hint as to how the client might communicate with the managing authenticator of the public key
         * credential the caller is referring to.
         * @param transports
         * @return 
         */
        public PublicKeyCredentialDescriptorBuilder transports(@Nonnull Optional<Set<AuthenticatorTransport>> transports) {
            this.transports = transports;
            return this;
        }

        /**Nonnull
         * An OPTIONAL hint as to how the client might communicate with the managing authenticator of the public key
         * credential the caller is referring to.
         * @param transports
         * @return 
         */
        public PublicKeyCredentialDescriptorBuilder transports(@Nonnull Set<AuthenticatorTransport> transports) {
            return this.transports(Optional.of(transports));
        }

        PublicKeyCredentialDescriptorBuilder() {
        }

        /**
         * The type of the credential the caller is referring to.
         * @param type
         * @return 
         */
        public PublicKeyCredentialDescriptorBuilder type(@Nonnull final PublicKeyCredentialType type) {
            this.type = type;
            return this;
        }

        /**
         * The credential ID of the public key credential the caller is referring to.
         * @param id
         * @return 
         */
        public PublicKeyCredentialDescriptorBuilder id(@Nonnull final ByteArray id) {
            this.id = id;
            return this;
        }

        public PublicKeyCredentialDescriptor build() {
            return new PublicKeyCredentialDescriptor(type, id, transports);
        }

    }

    public PublicKeyCredentialDescriptorBuilder toBuilder() {
        return new PublicKeyCredentialDescriptorBuilder().type(this.type).id(this.id).transports(this.transports);
    }

    /**
     * The type of the credential the caller is referring to.
     * @return 
     */
    @Nonnull
    public PublicKeyCredentialType getType() {
        return this.type;
    }

    /**
     * The credential ID of the public key credential the caller is referring to.
     * @return 
     */
    @Nonnull
    public ByteArray getId() {
        return this.id;
    }

    /**
     * An OPTIONAL hint as to how the client might communicate with the managing authenticator of the public key

     * credential the caller is referring to.
     * @return 
     */
    @Nonnull
    public Optional<Set<AuthenticatorTransport>> getTransports() {
        return this.transports;
    }
}
