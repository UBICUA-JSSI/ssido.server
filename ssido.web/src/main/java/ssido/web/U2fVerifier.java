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

package ssido.web;

import com.fasterxml.jackson.databind.JsonNode;
import ssido.util.CertificateParser;
import ssido.util.ExceptionUtil;
import ssido.util.JacksonCodecs;
import ssido.core.data.ByteArray;
import ssido.core.data.exception.Base64UrlException;
import ssido.core.extension.appid.AppId;
import ssido.core.BouncyCastleCrypto;
import ssido.core.U2fRawRegisterResponse;
import ssido.data.RegistrationRequest;
import ssido.data.U2fRegistrationResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class U2fVerifier {

    private static final BouncyCastleCrypto CRYPTO = new BouncyCastleCrypto();

    public static boolean verify(AppId appId,  RegistrationRequest request, U2fRegistrationResponse response) throws CertificateException, IOException, Base64UrlException {
        final ByteArray appIdHash = CRYPTO.hash(appId.getId());
        final ByteArray clientDataHash = CRYPTO.hash(response.getCredential().getU2fResponse().getClientDataJSON());

        final JsonNode clientData = JacksonCodecs.json().readTree(response.getCredential().getU2fResponse().getClientDataJSON().getBytes());
        final String challengeBase64 = clientData.get("challenge").textValue();

        ExceptionUtil.assure(
            request.getPublicKeyCredentialCreationOptions().getChallenge().equals(ByteArray.fromBase64Url(challengeBase64)),
            "Wrong challenge."
        );

        InputStream attestationCertAndSignatureStream = new ByteArrayInputStream(response.getCredential().getU2fResponse().getAttestationCertAndSignature().getBytes());

        final X509Certificate attestationCert = CertificateParser.parseDer(attestationCertAndSignatureStream);

        byte[] signatureBytes = new byte[attestationCertAndSignatureStream.available()];
        attestationCertAndSignatureStream.read(signatureBytes);
        final ByteArray signature = new ByteArray(signatureBytes);

        return new U2fRawRegisterResponse(
            response.getCredential().getU2fResponse().getPublicKey(),
            response.getCredential().getU2fResponse().getKeyHandle(),
            attestationCert,
            signature
        ).verifySignature(
            appIdHash,
            clientDataHash
        );
    }

}
