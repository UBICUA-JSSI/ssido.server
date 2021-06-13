/*
 *
 *  * Copyright 2021 UBICUA.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */
package ssido.core.data;

import ssido.core.data.AttestationObject;
import ssido.core.data.PublicKeyCredential;
import ssido.core.data.AuthenticatorAttestationResponse;
import ssido.core.data.ByteArray;
import ssido.core.data.ClientRegistrationExtensionOutputs;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import ssido.core.data.exception.Base64UrlException;
import ssido.util.BinaryUtil;
import java.io.IOException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import static org.junit.Assert.*;

/**
 *
 * @author Andrei
 */
public class PublicKeyCredentialTest {
    
    public PublicKeyCredentialTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test of builder method, of class PublicKeyCredential.
     * @throws java.io.IOException
     * @throws ssido.core.data.exception.Base64UrlException
     */
    @org.junit.Test
    public void testBuilder() throws IOException, Base64UrlException {
        
        ByteArray attestationObject = new ByteArray(BinaryUtil.fromHex("bf68617574684461746158a449960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f0020fa616cbe1c046d224524e773b386f9f3fd0d0fb6d4c20700023288034e48f093a52258208b02052aeec1d7cfaf1244d9b72296a6bfaf9542c132273c4be8fc01388ee8f30326010221582081906607ef7095eaa3dea2517cfc5a7c0c9768685e30ddb5865f2ada0f5cc63c200163666d74667061636b65646761747453746d74bf6373696758473045022010511b27bd566c7bcdf6e4f08ef2fe4ea20a56826b76761253bbcc31b0be1fa2022100b2659e3efc858fd4389dc48cd0651487f2e7bc4f5eba59db154bdcd0ae60c9d163616c6726ffff"));
        
        ObjectMapper mapper = new ObjectMapper();
        
        JsonNode tokenBinding = mapper.createObjectNode();
        ((ObjectNode) tokenBinding).put("status", "supported");

        JsonNode clientDataJson = mapper.createObjectNode();
        ((ObjectNode) clientDataJson).put("challenge", "AAEBAgMFCA0VIjdZEGl5Yls");
        ((ObjectNode) clientDataJson).put("origin", "https://localhost");
        ((ObjectNode) clientDataJson).put("type", "webauthn.create");
        ((ObjectNode) clientDataJson).set("type", tokenBinding);
        ((ObjectNode) clientDataJson).set("clientExtensions", mapper.createObjectNode());
        
        AuthenticatorAttestationResponse authenticatorAttestation = AuthenticatorAttestationResponse.builder()
                .attestationObject(attestationObject)
                .clientDataJSON(new ByteArray(mapper.writeValueAsString(clientDataJson).getBytes()))
                .build();
        
        PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> response = PublicKeyCredential.<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>builder()
                .id(new AttestationObject(attestationObject).getAuthenticatorData().getAttestedCredentialData().get().getCredentialId())
                .response(authenticatorAttestation)
                .clientExtensionResults(ClientRegistrationExtensionOutputs.builder().build())
                .build();
        
        assertNotNull(response);
    }

    /**
     * Test of parseRegistrationResponseJson method, of class PublicKeyCredential.
     */
    @org.junit.Test
    public void testParseRegistrationResponseJson() throws Exception {
//        System.out.println("parseRegistrationResponseJson");
//        String json = "";
//        PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> expResult = null;
//        PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> result = PublicKeyCredential.parseRegistrationResponseJson(json);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of parseAssertionResponseJson method, of class PublicKeyCredential.
     */
    @org.junit.Test
    public void testParseAssertionResponseJson() throws Exception {
//        System.out.println("parseAssertionResponseJson");
//        String json = "";
//        PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> expResult = null;
//        PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> result = PublicKeyCredential.parseAssertionResponseJson(json);
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }


    /**
     * Test of getId method, of class PublicKeyCredential.
     */
    @org.junit.Test
    public void testGetId() {
//        System.out.println("getId");
//        PublicKeyCredential instance = null;
//        ByteArray expResult = null;
//        ByteArray result = instance.getId();
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of getResponse method, of class PublicKeyCredential.
     */
    @org.junit.Test
    public void testGetResponse() {
//        System.out.println("getResponse");
//        PublicKeyCredential instance = null;
//        Object expResult = null;
//        Object result = instance.getResponse();
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of getClientExtensionResults method, of class PublicKeyCredential.
     */
    @org.junit.Test
    public void testGetClientExtensionResults() {
//        System.out.println("getClientExtensionResults");
//        PublicKeyCredential instance = null;
//        Object expResult = null;
//        Object result = instance.getClientExtensionResults();
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of getType method, of class PublicKeyCredential.
     */
    @org.junit.Test
    public void testGetType() {
//        System.out.println("getType");
//        PublicKeyCredential instance = null;
//        PublicKeyCredentialType expResult = null;
//        PublicKeyCredentialType result = instance.getType();
//        assertEquals(expResult, result);
//        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }
    
}
