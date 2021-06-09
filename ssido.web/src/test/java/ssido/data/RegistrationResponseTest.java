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
package ssido.data;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import ssido.core.data.AttestationObject;
import ssido.core.data.AuthenticatorAttestationResponse;
import ssido.core.data.ByteArray;
import ssido.core.data.ClientRegistrationExtensionOutputs;
import ssido.core.data.PublicKeyCredential;
import ssido.core.data.exception.Base64UrlException;
import ssido.util.BinaryUtil;
import java.io.IOException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Andrei
 */
public class RegistrationResponseTest {
    
    public RegistrationResponseTest() {
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
     * Test of getRequestId method, of class RegistrationResponse.
     * @throws java.io.IOException
     * @throws ssido.core.data.exception.Base64UrlException
     */
    @Test
    public void testRegistratonResponse() throws IOException, Base64UrlException {
        
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
        
        PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> publicKeyCredential = PublicKeyCredential.<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>builder()
                .id(new AttestationObject(attestationObject).getAuthenticatorData().getAttestedCredentialData().get().getCredentialId())
                .response(authenticatorAttestation)
                .clientExtensionResults(ClientRegistrationExtensionOutputs.builder().build())
                .build();
        
        ByteArray requestId = ByteArray.fromBase64Url("request1");
        
        RegistrationResponse registrationResponse = new RegistrationResponse(requestId, publicKeyCredential);
        assertNotNull(registrationResponse);
    }

    /**
     * Test of getCredential method, of class RegistrationResponse.
     * @throws ssido.core.data.exception.Base64UrlException
     * @throws java.io.IOException
     */
    @Test
    public void testRegistratonResponseJSON() throws Base64UrlException, IOException {
        ObjectMapper mapper = new ObjectMapper();
                
        ObjectNode authenticationAttestationResponse = mapper.createObjectNode();
        authenticationAttestationResponse.put("attestationObject", "v2hhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAFOQABAgMEBQYHCAkKCwwNDg8AIIjjhj6nH3qL2QF3tkUogilFykuaXjJTw35O4m-0NSX0pSJYIA5Nt8eYkLco-NQfKPXaA6dD9UfX_SHaYo-L-YQb78HsAyYBAiFYIOuzRl1o1Hem2jVRYhjkbSeIydhqLln9iltAgsDYjXRTIAFjZm10aGZpZG8tdTJmZ2F0dFN0bXS_Y3g1Y59ZAekwggHlMIIBjKADAgECAgIFOTAKBggqhkjOPQQDAjBqMSYwJAYDVQQDDB1ZdWJpY28gV2ViQXV0aG4gdW5pdCB0ZXN0cyBDQTEPMA0GA1UECgwGWXViaWNvMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMQswCQYDVQQGEwJTRTAeFw0xODA5MDYxNzQyMDBaFw0xODA5MDYxNzQyMDBaMGcxIzAhBgNVBAMMGll1YmljbyBXZWJBdXRobiB1bml0IHRlc3RzMQ8wDQYDVQQKDAZZdWJpY28xIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlNFMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJ-8bFED9TnFhaArujgB0foNaV4gQIulP1mC5DO1wvSByw4eOyXujpPHkTw9y5e5J2J3N9coSReZJgBRpvFzYD6MlMCMwIQYLKwYBBAGC5RwBAQQEEgQQAAECAwQFBgcICQoLDA0ODzAKBggqhkjOPQQDAgNHADBEAiB4bL25EH06vPBOVnReObXrS910ARVOLJPPnKNoZbe64gIgX1Rg5oydH45zEMEVDjNPStwv6Z3nE_isMeY-szlQhv3_Y3NpZ1hHMEUCIQDBs1nbSuuKQ6yoHMQoRp8eCT_HZvR45F_aVP6qFX_wKgIgMCL58bv-crkLwTwiEL9ibCV4nDYM-DZuW5_BFCJbcxn__w");
        
        ObjectNode tokenBinding = mapper.createObjectNode();
        tokenBinding.put("status", "supported");
        
        ObjectNode clientDataJson = mapper.createObjectNode();
        clientDataJson.put("challenge", "AAEBAgMFCA0VIjdZEGl5Yls");
        clientDataJson.put("origin", "https://localhost");
        clientDataJson.put("type", "webauthn.create");
        clientDataJson.set("tokenBinding", tokenBinding);
        clientDataJson.set("clientExtensions", mapper.createObjectNode());
        
        String clientDataString = new ObjectMapper().writeValueAsString(clientDataJson);
        authenticationAttestationResponse.put("clientDataJSON", new ByteArray(clientDataString.getBytes()).getBase64());
        
        
        ObjectNode publicKeyCredential = mapper.createObjectNode();
        publicKeyCredential.put("id", "iOOGPqcfeovZAXe2RSiCKUXKS5peMlPDfk7ib7Q1JfQ");
        publicKeyCredential.set("response", authenticationAttestationResponse);
        publicKeyCredential.set("clientExtensionResults", mapper.createObjectNode());
        publicKeyCredential.put("type", "public-key");
        
        ObjectNode response = mapper.createObjectNode();
        response.put("requestId", "request1");
        response.set("credential", publicKeyCredential);
        
        String result = mapper.writeValueAsString(response);
        assertNotNull(result);
    }
    
}
