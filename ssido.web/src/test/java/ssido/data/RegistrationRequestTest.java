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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import ssido.core.extension.appid.InvalidAppIdException;
import ssido.util.JacksonCodecs;
import ssido.web.SsidoService;
import ssido.web.util.Either;
import java.security.cert.CertificateException;
import java.util.Optional;
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
public class RegistrationRequestTest {
    
    RegistrationRequest request = null;
    private String  username;
    private String displayName;
    private Optional<String> credentialNickname;
    private boolean requireResidentKey;
    
    public RegistrationRequestTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() throws InvalidAppIdException, CertificateException {
        username = "caracola";
        displayName = "Caracola";
        credentialNickname = Optional.of("Caracola Credential");
        requireResidentKey = false;
        SsidoService server = new SsidoService();
        Either<String, RegistrationRequest> result = server.startRegistration(username, displayName, credentialNickname, Optional.empty(), requireResidentKey);
        request = result.right().get();
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test of getUsername method, of class RegistrationRequest.
     */
    @Test
    public void testGetUsername() {
        assertEquals(username, request.getUsername());
    }

    /**
     * Test of getCredentialNickname method, of class RegistrationRequest.
     */
    @Test
    public void testGetCredentialNickname() {
        assertEquals(credentialNickname, request.getCredentialNickname());
    }

    /**
     * Test of getRequestId method, of class RegistrationRequest.
     * @throws com.fasterxml.jackson.core.JsonProcessingException
     */
    @Test
    public void testGetJson() throws JsonProcessingException {
        ObjectMapper mapper = JacksonCodecs.json();
        String result = mapper.writeValueAsString(request);
        assertNotNull(result);
    }

    
}
