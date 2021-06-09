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
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import ssido.authenticator.util.JacksonCodecs;
import java.io.IOException;
import java.util.Base64;
import javax.annotation.Nonnull;

/**
 * Authenticators MUST provide some form of attestation. The basic requirement is that the authenticator can produce,
 * for each credential public key, an attestation statement verifiable by the WebAuthn Relying Party. Typically, this
 * attestation statement contains a signature by an attestation private key over the attested credential public key and
 * a challenge, as well as a certificate or similar data providing provenance information for the attestation public
 * key, enabling the Relying Party to make a trust decision. However, if an attestation key pair is not available, then
 * the authenticator MUST perform <a href="https://www.w3.org/TR/webauthn-2/#self-attestation">self
 * attestation</a> of the credential public key with the corresponding credential private key. All this information is
 * returned by authenticators any time a new public key credential is generated, in the overall form of an attestation
 * object. The relationship of the attestation object with authenticator data (containing attested credential data) and
 * the attestation statement is illustrated in <a href="https://www.w3.org/TR/webauthn-2//#fig-attStructs">figure 5</a>.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-2/#sctn-attestation">§6.4. Attestation</a>
 */
@JsonSerialize(using = AttestationObject.JsonSerializer.class)
public final class AttestationObject {

    private static final String FORMAT = "packed";
    /**
     * The authenticator data embedded inside this attestation object. This is one part of the signed data that the
     * signature in the attestation statement (if any) is computed over.
     */
    @Nonnull
    private final transient AuthenticatorData validatorData;
    
    /**
     * An important component of the attestation object is the attestation statement. This is a specific type of signed
     * data object, containing statements about a public key credential itself and the authenticator that created it. It
     * contains an attestation signature created using the key of the attesting authority (except for the case of self
     * attestation, when it is created using the credential private key).
     *
     * <p>
     * Users of this library should not need to access this value directly.
     * </p>
     */
    @Nonnull
    private final transient ObjectNode attestationStatement;

    
    private AttestationObject(@Nonnull AuthenticatorData validatorData, @Nonnull ObjectNode attestationStatement) {
        this.validatorData = validatorData;
        this.attestationStatement = attestationStatement;
    }
    
    public static AttestationObjectBuilder builder() {
        return new AttestationObjectBuilder();
    }

    public static class AttestationObjectBuilder {
        private AuthenticatorData validatorData;
        private ObjectNode attestationStatement;

        AttestationObjectBuilder() {
        }
        
        /**
         * The AuthenticatorData of the authenticator.
         * @param validatorData
         * @return 
         */
        public AttestationObjectBuilder validatorData(@Nonnull final AuthenticatorData validatorData) {
            this.validatorData = validatorData;
            return this;
        }
        
        /**
         * The ObjectNode of the authenticator.
         * @param attestationStatement
         * @return 
         */
        public AttestationObjectBuilder attestationStatement(@Nonnull final ObjectNode attestationStatement) {
            this.attestationStatement = attestationStatement;
            return this;
        }
        
        public AttestationObject build() {
            return new AttestationObject(validatorData, attestationStatement);
        }
    }
    /**
     * The original raw byte array that this object is decoded from.
     *
     * @return
     * @see <a href="https://www.w3.org/TR/webauthn-2/#sctn-attestation">§6.4. Attestation</a>
     */
    @Nonnull
    public byte[] getBytes() {
        
        byte[] bytes = new byte[0];
        
        JsonNodeFactory factory = JsonNodeFactory.instance;
        ObjectNode node = factory.objectNode();
        node.set("authData",  factory.binaryNode(validatorData.getBytes()));
        node.set("fmt",  factory.textNode(FORMAT));
        node.set("attStmt",  attestationStatement);
        
        try{
            bytes = JacksonCodecs.cbor().writeValueAsBytes(node);
        } catch(JsonProcessingException e){}
        return bytes;
    }
    
    static class JsonSerializer extends com.fasterxml.jackson.databind.JsonSerializer<AttestationObject> {
        @Override
        public void serialize(AttestationObject value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
            gen.writeString(Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes()));
        }
    }

    /**
     * The authenticator data embedded inside this attestation object. This is one part of the signed data that the
     * signature in the attestation statement (if any) is computed over.
     * @return 
     */
    @Nonnull
    public AuthenticatorData getAuthenticatorData() {
        return validatorData;
    }

    /**
     * The attestation statement format identifier of this attestation object.
     *
     * @return
     * @see <a href="https://www.w3.org/TR/webauthn-2/#defined-attestation-formats">§8. Defined
     * Attestation Statement Formats</a>
     *
     * <p>
     * Users of this library should not need to access this value directly.
     * </p>
     */
    @Nonnull
    public String getFormat() {
        return FORMAT;
    }

    /**
     * An important component of the attestation object is the attestation statement. This is a specific type of signed
     * data object, containing statements about a public key credential itself and the authenticator that created it. It
     * contains an attestation signature created using the key of the attesting authority (except for the case of self
     * attestation, when it is created using the credential private key).
     *
     * <p>
     * Users of this library should not need to access this value directly.
     * </p>
     * @return 
     */
    @Nonnull
    public ObjectNode getAttestationStatement() {
        return attestationStatement;
    }

}
