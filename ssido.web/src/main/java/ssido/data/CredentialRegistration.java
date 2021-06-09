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
package ssido.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import ssido.core.RegisteredCredential;
import ssido.core.attestation.Attestation;
import ssido.core.data.UserIdentity;
import java.time.Instant;
import java.util.Optional;

public final class CredentialRegistration {
    private final long signatureCount;
    private final UserIdentity userIdentity;
    private final Optional<String> credentialNickname;
    @JsonIgnore
    private final Instant registrationTime;
    private final RegisteredCredential credential;
    private final Optional<Attestation> attestationMetadata;

    @JsonProperty("registrationTime")
    public String getRegistrationTimestamp() {
        return registrationTime.toString();
    }

    public String getUsername() {
        return userIdentity.getName();
    }

    CredentialRegistration(final long signatureCount, final UserIdentity userIdentity, final Optional<String> credentialNickname, final Instant registrationTime, final RegisteredCredential credential, final Optional<Attestation> attestationMetadata) {
        this.signatureCount = signatureCount;
        this.userIdentity = userIdentity;
        this.credentialNickname = credentialNickname;
        this.registrationTime = registrationTime;
        this.credential = credential;
        this.attestationMetadata = attestationMetadata;
    }


    public static class CredentialRegistrationBuilder {
        private long signatureCount;
        private UserIdentity userIdentity;
        private Optional<String> credentialNickname;
        private Instant registrationTime;
        private RegisteredCredential credential;
        private Optional<Attestation> attestationMetadata;

        CredentialRegistrationBuilder() {
        }

        public CredentialRegistrationBuilder signatureCount(final long signatureCount) {
            this.signatureCount = signatureCount;
            return this;
        }

        public CredentialRegistrationBuilder userIdentity(final UserIdentity userIdentity) {
            this.userIdentity = userIdentity;
            return this;
        }

        public CredentialRegistrationBuilder credentialNickname(final Optional<String> credentialNickname) {
            this.credentialNickname = credentialNickname;
            return this;
        }

        public CredentialRegistrationBuilder registrationTime(final Instant registrationTime) {
            this.registrationTime = registrationTime;
            return this;
        }

        public CredentialRegistrationBuilder credential(final RegisteredCredential credential) {
            this.credential = credential;
            return this;
        }

        public CredentialRegistrationBuilder attestationMetadata(final Optional<Attestation> attestationMetadata) {
            this.attestationMetadata = attestationMetadata;
            return this;
        }

        public CredentialRegistration build() {
            return new CredentialRegistration(signatureCount, userIdentity, credentialNickname, registrationTime, credential, attestationMetadata);
        }
    }

    public static CredentialRegistrationBuilder builder() {
        return new CredentialRegistrationBuilder();
    }

    public long getSignatureCount() {
        return this.signatureCount;
    }

    public UserIdentity getUserIdentity() {
        return this.userIdentity;
    }

    public Optional<String> getCredentialNickname() {
        return this.credentialNickname;
    }

    public Instant getRegistrationTime() {
        return this.registrationTime;
    }

    public RegisteredCredential getCredential() {
        return this.credential;
    }

    public Optional<Attestation> getAttestationMetadata() {
        return this.attestationMetadata;
    }

    public CredentialRegistration withSignatureCount(final long signatureCount) {
        return this.signatureCount == signatureCount ? this : new CredentialRegistration(signatureCount, this.userIdentity, this.credentialNickname, this.registrationTime, this.credential, this.attestationMetadata);
    }

    public CredentialRegistration withUserIdentity(final UserIdentity userIdentity) {
        return this.userIdentity == userIdentity ? this : new CredentialRegistration(this.signatureCount, userIdentity, this.credentialNickname, this.registrationTime, this.credential, this.attestationMetadata);
    }

    public CredentialRegistration withCredentialNickname(final Optional<String> credentialNickname) {
        return this.credentialNickname == credentialNickname ? this : new CredentialRegistration(this.signatureCount, this.userIdentity, credentialNickname, this.registrationTime, this.credential, this.attestationMetadata);
    }

    public CredentialRegistration withRegistrationTime(final Instant registrationTime) {
        return this.registrationTime == registrationTime ? this : new CredentialRegistration(this.signatureCount, this.userIdentity, this.credentialNickname, registrationTime, this.credential, this.attestationMetadata);
    }

    public CredentialRegistration withCredential(final RegisteredCredential credential) {
        return this.credential == credential ? this : new CredentialRegistration(this.signatureCount, this.userIdentity, this.credentialNickname, this.registrationTime, credential, this.attestationMetadata);
    }

    public CredentialRegistration withAttestationMetadata(final Optional<Attestation> attestationMetadata) {
        return this.attestationMetadata == attestationMetadata ? this : new CredentialRegistration(this.signatureCount, this.userIdentity, this.credentialNickname, this.registrationTime, this.credential, attestationMetadata);
    }
}
