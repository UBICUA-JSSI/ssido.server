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
import ssido.data.AssertionRequestWrapper;
import ssido.data.RegistrationRequest;
import ssido.authenticator.Authenticator;
import ssido.authenticator.util.CryptoUtil;
import ssido.util.JacksonCodecs;
import ssido.web.SsidoService.SuccessfulAuthenticationResult;
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
import static ssido.web.WebAuthnConfig.AUTHENTICATE;
import static ssido.web.WebAuthnConfig.REGISTER;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author Andrei
 */
public class AuthenticatorServerTest {
    
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
    
    private SsidoService server;

    
    public AuthenticatorServerTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
        NaCl.sodium();
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() throws Base64UrlException, InvalidAppIdException, CertificateException {
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
        
        server = new SsidoService();
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test of testStartAuthentication method, of class SsidoService.
     * @throws ssido.core.extension.appid.InvalidAppIdException
     * @throws java.security.cert.CertificateException
     * @throws com.fasterxml.jackson.core.JsonProcessingException
     * @throws ssido.core.data.exception.Base64UrlException
     */
    @Test
    public void testValidation() throws InvalidAppIdException, CertificateException, JsonProcessingException, IOException, Base64UrlException {
       
        AssertionRequestWrapper assertionRequest = startValidation();
        
        String requestId = assertionRequest.getRequestId().getBase64Url();
        ByteArray challenge = assertionRequest.getPublicKeyCredentialRequestOptions().getChallenge();
        String rpId = assertionRequest.getPublicKeyCredentialRequestOptions().getRpId().get();
        
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new Jdk8Module());
        
        ObjectNode tokenBinding = mapper.createObjectNode();
        tokenBinding.put("status", "supported");
        
        ObjectNode clientDataJson = mapper.createObjectNode();
        clientDataJson.put("challenge", challenge.getBase64Url());
        clientDataJson.put("origin", AUTHENTICATE);
        clientDataJson.put("type", "webauthn.get");
        clientDataJson.set("tokenBinding", tokenBinding);
        clientDataJson.set("clientExtensions", mapper.createObjectNode());

        String clientDataString = new ObjectMapper().writeValueAsString(clientDataJson);
        
        Authenticator authenticator = Authenticator.builder()
                .publicKey(publicKey)
                .rpId(rpId.getBytes())
                .counter(1)
                .attestationStatement(privateKey, clientDataString.getBytes())
                .build();
        
           
        byte[] signature = authenticator.getAttestationStatement().getObjectNode().get("sig").binaryValue();
        
        ObjectNode authenticatorAssertionResponse = mapper.createObjectNode();
        authenticatorAssertionResponse.put("authenticatorData", Base64.getUrlEncoder().withoutPadding().encodeToString(authenticator.getAuthenticatorData().getBytes()));
        authenticatorAssertionResponse.put("clientDataJSON", new ByteArray(clientDataString.getBytes()).getBase64());
        authenticatorAssertionResponse.put("signature", Base64.getUrlEncoder().withoutPadding().encodeToString(signature));
        
        ObjectNode publicKeyCredential = mapper.createObjectNode();
        publicKeyCredential.put("id", "iOOGPqcfeovZAXe2RSiCKUXKS5peMlPDfk7ib7Q1JfQ");
        publicKeyCredential.set("response", authenticatorAssertionResponse);
        publicKeyCredential.set("clientExtensionResults", mapper.createObjectNode()); 
        publicKeyCredential.put("type", "public-key");
        
        LOG.debug(String.format("PublicKeyCredential: %s", mapper.writeValueAsString(publicKeyCredential)));
        
      
        ObjectNode response = mapper.createObjectNode();
        response.put("requestId", requestId);
        response.set("credential", publicKeyCredential);
        
        Either<List<String>, SsidoService.SuccessfulAuthenticationResult> result = server.finishAuthentication(mapper.writeValueAsString(response));
        SuccessfulAuthenticationResult authentication = result.right().get();
        assertNotNull(authentication);
    }
    
    private AssertionRequestWrapper startValidation() throws JsonProcessingException{
        Either<String, RegistrationRequest> request = server.startRegistration(username, displayName, credentialNickname, Optional.empty(), requireResidentKey);
        
        RegistrationRequest registrationRequest = request.right().get();
        
        String requestId = registrationRequest.getRequestId().getBase64Url();
        ByteArray challenge = registrationRequest.getPublicKeyCredentialCreationOptions().getChallenge();
        RelyingPartyIdentity identity = registrationRequest.getPublicKeyCredentialCreationOptions().getRp();
        
        ObjectMapper mapper = new ObjectMapper();
        
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
        mapper.registerModule(new Jdk8Module());

        response.put("requestId", requestId);
        response.set("credential", publicKeyCredential);
        
        Either<List<String>, SuccessfulRegistrationResult> result = server.finishRegistration(mapper.writeValueAsString(response));
        SuccessfulRegistrationResult registration = result.right().get();
        assertNotNull(registration);
        
        Either<List<String>, AssertionRequestWrapper> startAuthentication = server.startAuthentication(Optional.of(username), Optional.empty());
        LOG.debug(String.format("Attestation request: %s", mapper.writeValueAsString(startAuthentication.right().get())));
        LOG.debug(String.format("PublicKeyCredentialRequestOptions: %s", mapper.writeValueAsString(startAuthentication.right().get().getPublicKeyCredentialRequestOptions())));
        return startAuthentication.right().get();
    }
 }
