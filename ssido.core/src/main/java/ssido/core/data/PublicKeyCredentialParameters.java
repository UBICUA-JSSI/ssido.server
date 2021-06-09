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

import com.fasterxml.jackson.annotation.JsonProperty;
import javax.annotation.Nonnull;

/**
 * Used to supply additional parameters when creating a new credential.
 *
 * @see <a href="https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialparameters">§5.3.
 * Parameters for Credential Generation (dictionary PublicKeyCredentialParameters)
 * </a>
 */
public final class PublicKeyCredentialParameters {
    /**
     * Specifies the cryptographic signature algorithm with which the newly generated credential will be used, and thus
     * also the type of asymmetric key pair to be generated, e.g., RSA or Elliptic Curve.
     */
    @Nonnull
    private final COSEAlgorithmIdentifier alg;
    /**
     * Specifies the type of credential to be created.
     */
    @Nonnull
    private final PublicKeyCredentialType type;

    private PublicKeyCredentialParameters(@Nonnull @JsonProperty("alg") COSEAlgorithmIdentifier alg, @Nonnull @JsonProperty("type") PublicKeyCredentialType type) {
        this.alg = alg;
        this.type = type;
    }

    /**
     * Algorithm {@link COSEAlgorithmIdentifier#EdDSA} and type {@link PublicKeyCredentialType#PUBLIC_KEY}.
     */
    public static final PublicKeyCredentialParameters EdDSA = builder().alg(COSEAlgorithmIdentifier.EdDSA).build();
    /**
     * Algorithm {@link COSEAlgorithmIdentifier#ES256} and type {@link PublicKeyCredentialType#PUBLIC_KEY}.
     */
    public static final PublicKeyCredentialParameters ES256 = builder().alg(COSEAlgorithmIdentifier.ES256).build();
    /**
     * Algorithm {@link COSEAlgorithmIdentifier#RS256} and type {@link PublicKeyCredentialType#PUBLIC_KEY}.
     */
    public static final PublicKeyCredentialParameters RS256 = builder().alg(COSEAlgorithmIdentifier.RS256).build();

    public static PublicKeyCredentialParametersBuilder.MandatoryStages builder() {
        return new PublicKeyCredentialParametersBuilder.MandatoryStages();
    }

    public static class PublicKeyCredentialParametersBuilder {
        private COSEAlgorithmIdentifier alg;
        private PublicKeyCredentialType type = PublicKeyCredentialType.PUBLIC_KEY;


        public static class MandatoryStages {
            private final PublicKeyCredentialParametersBuilder builder = new PublicKeyCredentialParametersBuilder();
            public PublicKeyCredentialParametersBuilder alg(COSEAlgorithmIdentifier alg) {
                return builder.alg(alg);
            }
        }

        PublicKeyCredentialParametersBuilder() {
        }

        /**
         * Specifies the cryptographic signature algorithm with which the newly generated credential will be used, and thus
         * also the type of asymmetric key pair to be generated, e.g., RSA or Elliptic Curve.
         * @param alg
         * @return 
         */
        public PublicKeyCredentialParametersBuilder alg(@Nonnull final COSEAlgorithmIdentifier alg) {
            this.alg = alg;
            return this;
        }

        /**
         * Specifies the type of credential to be created.
         * @param type
         * @return 
         */
        public PublicKeyCredentialParametersBuilder type(@Nonnull final PublicKeyCredentialType type) {
            this.type = type;
            return this;
        }

        public PublicKeyCredentialParameters build() {
            return new PublicKeyCredentialParameters(alg, type);
        }

        
    }

    public PublicKeyCredentialParametersBuilder toBuilder() {
        return new PublicKeyCredentialParametersBuilder().alg(this.alg).type(this.type);
    }

    /**
     * Specifies the cryptographic signature algorithm with which the newly generated credential will be used, and thus
     * also the type of asymmetric key pair to be generated, e.g., RSA or Elliptic Curve.
     * @return 
     */
    @Nonnull
    public COSEAlgorithmIdentifier getAlg() {
        return this.alg;
    }

    /**
     * Specifies the type of credential to be created.
     * @return 
     */
    @Nonnull
    public PublicKeyCredentialType getType() {
        return this.type;
    }
}