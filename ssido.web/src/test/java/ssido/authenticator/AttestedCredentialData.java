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

package ssido.authenticator;

import ssido.authenticator.util.CryptoUtil;
import java.security.PublicKey;
import javax.annotation.Nonnull;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

/**
 * Attested credential data is a variable-length byte array added to the authenticator data when generating an
 * attestation object for a given credential. This class provides access to the three data segments of that byte array.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-2/#sec-attested-credential-data">6.4.1. Attested
 * Credential Data</a>
 */
public final class AttestedCredentialData {
    /**
     * The AAGUID of the authenticator.
     */
    @Nonnull
    private final byte[] aaguid;
    /**
     * The credential ID of the attested credential.
     */
    @Nonnull
    private final byte[] credentialId;
    // TODO: verify requirements https://www.w3.org/TR/webauthn-2/#sec-attestation-data
    /**
     * The credential public key encoded in COSE_Key format, as defined in Section 7 of <a
     * href="https://tools.ietf.org/html/rfc8152">RFC 8152</a>.
     */
    @Nonnull
    private final byte[] publicKey;

    private AttestedCredentialData(@Nonnull byte[] aaguid, @Nonnull byte[] credentialId, @Nonnull byte[] publicKey) {
        this.aaguid = aaguid;
        this.credentialId = credentialId;
        this.publicKey = publicKey;
    }

    public static AttestedCredentialDataBuilder builder() {
        return new AttestedCredentialDataBuilder();
    }

    public static class AttestedCredentialDataBuilder {
        private byte[] aaguid;
        private byte[] credentialId;
        private byte[] publicKey;

        AttestedCredentialDataBuilder() {
        }

        /**
         * The AAGUID of the authenticator.
         * @param aaguid
         * @return 
         */
        public AttestedCredentialDataBuilder aaguid(@Nonnull final byte[] aaguid) {
            this.aaguid = aaguid;
            return this;
        }

        /**
         * The credential ID of the attested credential.
         * @param credentialId
         * @return 
         */
        public AttestedCredentialDataBuilder credentialId(@Nonnull final byte[] credentialId) {
            this.credentialId = credentialId;
            return this;
        }

        /**
         * The credential public key encoded in COSE_Key format, as defined in Section 7 of <a
         * href="https://tools.ietf.org/html/rfc8152">RFC 8152</a>.
         * @param publicKey
         * @return 
         */
        public AttestedCredentialDataBuilder publicKey(@Nonnull final byte[] publicKey) {
            
            EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("Ed25519");
            PublicKey pk = new EdDSAPublicKey(new EdDSAPublicKeySpec(publicKey, spec));
            this.publicKey = AuthenticatorCodec.publicKeyToCose(pk);
            this.credentialId = CryptoUtil.sha256(publicKey);
            return this;
        }

        public AttestedCredentialData build() {
            return new AttestedCredentialData(aaguid, credentialId, publicKey);
        }
    }

    /**
     * The AAGUID of the authenticator.
     * @return 
     */
    @Nonnull
    public byte[] getAaguid() {
        return this.aaguid;
    }

    /**
     * The credential ID of the attested credential.
     * @return 
     */
    @Nonnull
    public byte[] getCredentialId() {
        return this.credentialId;
    }

    /**
     * The credential public key encoded in COSE_Key format, as defined in Section 7 of <a
     * href="https://tools.ietf.org/html/rfc8152">RFC 8152</a>.
     * @return 
     */
    @Nonnull
    public byte[] publicKey() {
        return this.publicKey;
    }
    
    public byte[] getBytes(){
        
        byte[] result = CryptoUtil.concat(
                aaguid, 
                CryptoUtil.encodeUint16((short)credentialId.length), 
                credentialId, 
                publicKey);
        
        return result;
    }
}
