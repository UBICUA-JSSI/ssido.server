/*
 * The MIT License
 *
 * Copyright 2019 ITON Solutions.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package ssido.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;

import ssido.core.data.ByteArray;
import ssido.core.data.RelyingPartyIdentity;
import ssido.core.data.exception.Base64UrlException;
import ssido.core.extension.appid.InvalidAppIdException;
import ssido.data.RegistrationRequest;
import ssido.data.StartRegistrationRequest;
import ssido.authenticator.Authenticator;
import ssido.authenticator.util.CryptoUtil;
import ssido.util.JacksonCodecs;
import ssido.web.SsidoService.SuccessfulRegistrationResult;
import ssido.web.util.Either;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Optional;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.libsodium.jni.NaCl;
import static ssido.web.WebAuthnConfig.REGISTER;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Andrei
 */
public class RegistrationServerTest {
    
    private static final Logger LOG = LoggerFactory.getLogger(SsidoService.class);
    
    private ObjectMapper jsonMapper;
    private String  username;
    private String displayName;
    private Optional<String> credentialNickname;
    private boolean requireResidentKey;
    private ByteArray requestId;
    private RelyingPartyIdentity rpId;
    private Set<String> origins = new HashSet<>();
    private Optional appId;
    private byte[] publicKey;
    private byte[] privateKey;

    
    public RegistrationServerTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
        NaCl.sodium();
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() throws Base64UrlException {
        jsonMapper = JacksonCodecs.json();
        username = "caracola";
        displayName = "Caracola";
        credentialNickname = Optional.of("Caracola Credential");
        requireResidentKey = false;
        requestId = ByteArray.fromBase64Url("request1");
        rpId = RelyingPartyIdentity.builder()
                .id("localhost")
                .name("Ubicua party").build();
        
        origins.add("localhost");
        appId = Optional.empty();
        publicKey  = CryptoUtil.fromHex("f10645012f49752b451c604d2057893f485b30a19a0bc3b4404bc969859874cb");
        privateKey = CryptoUtil.fromHex("8f243ae3ee3218dcff652c1971215da45e69018514a49c38afd953d8e3169edff10645012f49752b451c604d2057893f485b30a19a0bc3b4404bc969859874cb");
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test of startRegistration method, of class SsidoService.
     * @throws ssido.core.extension.appid.InvalidAppIdException
     * @throws java.security.cert.CertificateException
     * @throws com.fasterxml.jackson.core.JsonProcessingException
     */
    @Test
    public void testStartRegistration() throws InvalidAppIdException, CertificateException, JsonProcessingException {
        SsidoService server = new SsidoService();
        Either<String, RegistrationRequest> request = server.startRegistration(username, displayName, credentialNickname, Optional.empty(), requireResidentKey);
        ObjectMapper mapper = JacksonCodecs.json();
        String json = mapper.writeValueAsString(new StartRegistrationRequest(request.right().get()));
        assertNotNull(json);
    }

    /**
     * Test of finishRegistration method, of class SsidoService.
     * @throws ssido.core.extension.appid.InvalidAppIdException
     * @throws java.security.cert.CertificateException
     * @throws com.fasterxml.jackson.core.JsonProcessingException
     * @throws ssido.core.data.exception.Base64UrlException
     */
    @Test
    public void testFinishRegistration() throws InvalidAppIdException, CertificateException, JsonProcessingException, IOException, Base64UrlException {
       
        SsidoService server = new SsidoService();
        Either<String, RegistrationRequest> request = server.startRegistration(username, displayName, credentialNickname, Optional.empty(), requireResidentKey);
        
        RegistrationRequest registrationRequest = request.right().get();
        
        String requestId = registrationRequest.getRequestId().getBase64Url();
        ByteArray challenge = registrationRequest.getPublicKeyCredentialCreationOptions().getChallenge();
        RelyingPartyIdentity identity = registrationRequest.getPublicKeyCredentialCreationOptions().getRp();
        
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new Jdk8Module());

        LOG.debug(String.format("PublicKeyCredentialCreationOptions: %s", mapper.writeValueAsString(registrationRequest.getPublicKeyCredentialCreationOptions())));
        
        ObjectNode tokenBinding = mapper.createObjectNode();
        tokenBinding.put("status", "supported");
        
        ObjectNode clientDataJson = mapper.createObjectNode();
        clientDataJson.put("challenge", challenge.getBase64Url());
        clientDataJson.put("origin", REGISTER);
        clientDataJson.put("type", "webauthn.create");
        clientDataJson.set("tokenBinding", tokenBinding);
        clientDataJson.set("clientExtensions", mapper.createObjectNode());

        String clientDataString = new ObjectMapper().writeValueAsString(clientDataJson);
        
        Authenticator authenticator = Authenticator.builder()
                .publicKey(publicKey)
                .rpId(identity.getId().getBytes())
                .counter(0)
                .attestationStatement(privateKey, clientDataString.getBytes())
                .build();
        
        ObjectNode authenticationAttestationResponse = mapper.createObjectNode();
        authenticationAttestationResponse.put("attestationObject", Base64.getUrlEncoder().withoutPadding().encodeToString(authenticator.getAttestationObject().getBytes()));
        authenticationAttestationResponse.put("clientDataJSON", new ByteArray(clientDataString.getBytes()).getBase64());
        
        ObjectNode publicKeyCredential = mapper.createObjectNode();
        publicKeyCredential.put("id", "iOOGPqcfeovZAXe2RSiCKUXKS5peMlPDfk7ib7Q1JfQ");
        publicKeyCredential.set("response", authenticationAttestationResponse);
        publicKeyCredential.set("clientExtensionResults", mapper.createObjectNode());
        publicKeyCredential.put("type", "public-key");
        
        ObjectNode response = mapper.createObjectNode();
        response.put("requestId", requestId);
        response.set("credential", publicKeyCredential);
        
        Either<List<String>, SuccessfulRegistrationResult> result = server.finishRegistration(mapper.writeValueAsString(response));
        SuccessfulRegistrationResult registration = result.right().get();
        assertNotNull(registration);
    }
}
