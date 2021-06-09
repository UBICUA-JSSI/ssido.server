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
package ssido.core.data;

import ssido.core.data.ByteArray;
import ssido.core.data.AuthenticatorData;
import ssido.core.data.AttestationObject;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import ssido.core.data.exception.Base64UrlException;
import java.io.IOException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author ITON Solutions
 */
public class AttestationObjectTest {
    
    AttestationObject attestationObject = null;
    String serialized = null;
    ByteArray data = null;
    
    public AttestationObjectTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() throws Base64UrlException, IOException {
        serialized = "v2hhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAFOQABAgMEBQYHCAkKCwwNDg8AIIjjhj6nH3qL2QF3tkUogilFykuaXjJTw35O4m-0NSX0pSJYIA5Nt8eYkLco-NQfKPXaA6dD9UfX_SHaYo-L-YQb78HsAyYBAiFYIOuzRl1o1Hem2jVRYhjkbSeIydhqLln9iltAgsDYjXRTIAFjZm10aGZpZG8tdTJmZ2F0dFN0bXS_Y3g1Y59ZAekwggHlMIIBjKADAgECAgIFOTAKBggqhkjOPQQDAjBqMSYwJAYDVQQDDB1ZdWJpY28gV2ViQXV0aG4gdW5pdCB0ZXN0cyBDQTEPMA0GA1UECgwGWXViaWNvMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMQswCQYDVQQGEwJTRTAeFw0xODA5MDYxNzQyMDBaFw0xODA5MDYxNzQyMDBaMGcxIzAhBgNVBAMMGll1YmljbyBXZWJBdXRobiB1bml0IHRlc3RzMQ8wDQYDVQQKDAZZdWJpY28xIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlNFMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJ-8bFED9TnFhaArujgB0foNaV4gQIulP1mC5DO1wvSByw4eOyXujpPHkTw9y5e5J2J3N9coSReZJgBRpvFzYD6MlMCMwIQYLKwYBBAGC5RwBAQQEEgQQAAECAwQFBgcICQoLDA0ODzAKBggqhkjOPQQDAgNHADBEAiB4bL25EH06vPBOVnReObXrS910ARVOLJPPnKNoZbe64gIgX1Rg5oydH45zEMEVDjNPStwv6Z3nE_isMeY-szlQhv3_Y3NpZ1hHMEUCIQDBs1nbSuuKQ6yoHMQoRp8eCT_HZvR45F_aVP6qFX_wKgIgMCL58bv-crkLwTwiEL9ibCV4nDYM-DZuW5_BFCJbcxn__w";
        data = ByteArray.fromBase64Url(serialized);
        attestationObject = new AttestationObject(data);
    }
    
    @After
    public void tearDown() {
    }
    
    @Test
    public void testAttestationObject() throws IOException, Base64UrlException{
        ByteArray data = ByteArray.fromBase64Url("v2hhdXRoRGF0YViN6iEBoq3QlAP2aRvKwfoea8zK0oXRiJ_bdH8lSn9V-XlAAAAAAAABAgMEBQYHCAkKCwwNDg8AIPvu4IexbxfHHfiSUt8cR0al6uvEu5RxzYimYuqH2PWwpAMnAQEgBiFYLDAqMAUGAytlcAMhAPEGRQEvSXUrRRxgTSBXiT9IWzChmgvDtEBLyWmFmHTLY2ZtdGZwYWNrZWRnYXR0U3RtdL9jc2lnWECj_MkeXcTBieH3hRfaTYP8-lkYk79hFvx8rJavHDx7EWKCIsanbGwz_xZD18tMfjLWXdvYbjfd_vavu2rPOWsBY2FsZyf__w");
        
        AttestationObject object = new AttestationObject(data);
        assertNotNull(object);
        AuthenticatorData authenticatorData = object.getAuthenticatorData();
        assertNotNull(authenticatorData);
        ObjectNode attestationStatement = object.getAttestationStatement();
        String result = new ObjectMapper().writeValueAsString(attestationStatement);
        assertNotNull(result);
        String format = object.getFormat();
        assertNotNull(format);
    }

    /**
     * Test of getBytes method, of class AttestationObject.
     */
    @Test
    public void testGetBytes() {
        String result = new ByteArray(attestationObject.getBytes().getBytes()).getBase64Url();
        assertEquals(result, serialized);
    }

    /**
     * Test of getAuthenticatorData method, of class AttestationObject.
     */
    @Test
    public void testGetAuthenticatorData() {
        AuthenticatorData authenticatorData = attestationObject.getAuthenticatorData();
        assertNotNull(authenticatorData);
    }
    
    /**
     * Test of createAuthenticatorData method, of class AttestationObject.
     */
    @Test
    public void testCreateAuthenticatorData() {
       String rpId = "localhost:8443";
       String origin = String.format("https://%s", rpId);
       ByteArray aaguid = new ByteArray(new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15});
       assertEquals("AAECAwQFBgcICQoLDA0ODw", aaguid.getBase64Url());
       ByteArray challenge = new ByteArray(new byte[]{0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 16, 105, 121, 98, 91});
       assertEquals("AAEBAgMFCA0VIjdZEGl5Yls", challenge.getBase64Url());
       
    }

    /**
     * Test of getFormat method, of class AttestationObject.
     */
    @Test
    public void testGetFormat() {
        
        String format = attestationObject.getFormat();
        assertNotNull(format);
    }

    /**
     * Test of getAttestationStatement method, of class AttestationObject.
     * @throws com.fasterxml.jackson.core.JsonProcessingException
     */
    @Test
    public void testGetAttestationStatement() throws JsonProcessingException {
        
        ObjectNode attestationStatement = attestationObject.getAttestationStatement();
        String result = new ObjectMapper().writeValueAsString(attestationStatement);
        assertNotNull(result);
    }
}
