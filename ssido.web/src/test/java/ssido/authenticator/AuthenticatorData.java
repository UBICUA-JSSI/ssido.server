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

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.upokecenter.cbor.CBORObject;
import ssido.authenticator.util.CryptoUtil;
import java.io.IOException;
import java.util.Base64;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * The authenticator data structure is a byte array of 37 bytes or more. This
 * class presents the authenticator data decoded as a high-level object.
 *
 * <p>
 * The authenticator data structure encodes contextual bindings made by the
 * authenticator. These bindings are controlled by the authenticator itself, and
 * derive their trust from the WebAuthn Relying Party's assessment of the
 * security properties of the authenticator. In one extreme case, the
 * authenticator may be embedded in the client, and its bindings may be no more
 * trustworthy than the client data. At the other extreme, the authenticator may
 * be a discrete entity with high-security hardware and software, connected to
 * the client over a secure channel. In both cases, the Relying Party receives
 * the authenticator data in the same format, and uses its knowledge of the
 * authenticator to make trust decisions.
 * </p>
 *
 * @see <a href="https://www.w3.org/TR/webauthn-2/#sec-authenticator-data">§6.1.
 * Authenticator Data</a>
 */

@JsonSerialize(using = AuthenticatorData.JsonSerializer.class)
public final class AuthenticatorData {

    /**
     * The original raw byte array that this object is decoded from. This is a
     * byte array of 37 bytes or more.
     *
     * @see
     * <a href="https://www.w3.org/TR/webauthn-2/#sec-authenticator-data">§6.1.
     * Authenticator Data</a>
     */
    @Nonnull
    private final byte[] rpId;
    /**
     * The 32-bit unsigned signature counter.
     *
     * @return
     */
    private byte[] counter;

    /**
     * The flags bit field.
     */
    @Nonnull
    private transient AuthenticatorDataFlags flags;
    /**
     * Attested credential data, if present.
     *
     * <p>
     * This member is present if and only if the
     * {@link AuthenticatorDataFlags#AT} flag is set.
     * </p>
     *
     * @see #flags
     */
    @Nonnull
    private transient AttestedCredentialData attestedCredentialData;
    
    @Nonnull
    private Optional<CBORObject> extensions;

    private AuthenticatorData(@Nonnull byte[] rpId, @Nonnull AttestedCredentialData attestedCredentialData) {
        this.rpId = rpId;
        this.flags = AuthenticatorDataFlags.builder().build();
        this.counter = CryptoUtil.encodeUint32(0);
        this.attestedCredentialData = attestedCredentialData;
        this.extensions = Optional.empty();
    }

    public static AuthenticatorDataBuilder builder() {
        return new AuthenticatorDataBuilder();
    }

    public static class AuthenticatorDataBuilder {

        private byte[] rpId;
        private AttestedCredentialData attestedCredentialData;

        AuthenticatorDataBuilder() {}

        /**
         * The rpId of the replying party.
         *
         * @param rpId
         * @return
         */
        public AuthenticatorDataBuilder rpId(@Nonnull final byte[] rpId) {
            this.rpId = rpId;
            return this;
        }

        /**
         * The AttestedCredentialData of the attested credential.
         *
         * @param attestedCredentialData
         * @return
         */
        public AuthenticatorDataBuilder attestedCredentialData(@Nonnull final AttestedCredentialData attestedCredentialData) {
            this.attestedCredentialData = attestedCredentialData;
            return this;
        }

        public AuthenticatorData build() {
            return new AuthenticatorData(rpId, attestedCredentialData);
        }
    }

    /**
     * The SHA-256 hash of the RP ID the credential is scoped to.
     *
     * @return
     */
    public byte[] getRpIdHash() {
        return CryptoUtil.sha256(rpId);
    }

    /**
     * The 32-bit unsigned signature counter.
     *
     * @return
     */
    public int getCounter() {
        return CryptoUtil.getUint32(counter);
    }
    
    public void setCounter(int counter){
        this.counter = CryptoUtil.encodeUint32(counter);
    }

    /**
     * Extension-defined authenticator data, if present.
     *
     * <p>
     * This member is present if and only if the
     * {@link AuthenticatorDataFlags#ED} flag is set.
     * </p>
     *
     * <p>
     * Changes to the returned value are not reflected in the
     * {@link AuthenticatorData} object.
     * </p>
     *
     * @return
     * @see #flags
     */
    public Optional<CBORObject> getExtensions() {
        return extensions;
    }
    
    public void setExtensions(Optional<CBORObject> extensions){
        this.extensions = extensions;
    }
    
    static class JsonSerializer extends com.fasterxml.jackson.databind.JsonSerializer<AuthenticatorData> {
        @Override
        public void serialize(AuthenticatorData value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
            gen.writeString(Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes()));
        }
    }

    /**
     * The original raw byte array that this object is decoded from. This is a
     * byte array of 37 bytes or more.
     *
     * @return
     * @see
     * <a href="https://www.w3.org/TR/webauthn-2/#sec-authenticator-data">§6.1.
     * Authenticator Data</a>
     */
    @Nonnull
    public byte[] getBytes() {

        byte[] result = CryptoUtil.concat(
                getRpIdHash(),
                getFlags().getBytes(),
                counter);

        if (attestedCredentialData != null) {
            result = CryptoUtil.concat(result, attestedCredentialData.getBytes());
        }
        if (extensions.isPresent()) {
            result = CryptoUtil.concat(result, extensions.get().EncodeToBytes());
        }
        return result;
    }

    /**
     * The flags bit field.
     *
     * @return
     */
    @Nonnull
    public AuthenticatorDataFlags getFlags() {
        return flags;
    }
    public void setFlags(AuthenticatorDataFlags flags){
        this.flags = flags;
    }

    /**
     * Attested credential data, if present.
     *
     * <p>
     * This member is present if and only if the
     * {@link AuthenticatorDataFlags#AT} flag is set.
     * </p>
     *
     * @return
     * @see #flags
     */
    @Nonnull
    public AttestedCredentialData getAttestedCredentialData() {
        return attestedCredentialData;
    }
    
    
}
