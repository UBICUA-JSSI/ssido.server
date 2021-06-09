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

import ssido.core.data.AssertionExtensionInputs;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import ssido.core.data.AssertionExtensionInputs.AssertionExtensionInputsBuilder;
import ssido.core.extension.appid.AppId;
import ssido.core.extension.appid.InvalidAppIdException;
import ssido.util.JacksonCodecs;
import java.io.IOException;
import java.util.Optional;
import java.util.Set;
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
public class AssertionExtensionInputsTest {
    
    String data = "{\"request\":{\"requestId\":\"s07QJ83gXYNwf2Il4a0lUONdc8-wN1RyVVNVQd0v\",\"publicKeyCredentialRequestOptions\":{\"challenge\":\"_6aQ2WgZOW19AdFLs1eCpeBWc5FFiqJhrk1x-KLAKhE\",\"rpId\":\"ubicua.com\",\"allowCredentials\":[{\"type\":\"public-key\",\"id\":\"iOOGPqcfeovZAXe2RSiCKUXKS5peMlPDfk7ib7Q1JfQ\"}],\"userVerification\":\"preferred\",\"extensions\":{\"appid\":\"https://ubicua.com:8443\"}},\"username\":\"vladimir\"},\"success\":true,\"action\":\"wss://176.84.169.249:8443/webauthn/authenticate/finish\"}}";
    ObjectMapper mapper = JacksonCodecs.json();
    
    public AssertionExtensionInputsTest() {
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
     * Test of getExtensionIds method, of class AssertionExtensionInputs.
     */
    @Test
    public void testDeserialize() throws IOException {
        StartAuthenticationRequest request = mapper.readValue(data, StartAuthenticationRequest.class);
        assertNotNull(request);
    }

    /**
     * Test of builder method, of class AssertionExtensionInputs.
     * @throws ssido.core.extension.appid.InvalidAppIdException
     * @throws com.fasterxml.jackson.core.JsonProcessingException
     */
    @Test
    public void testSerialize() throws InvalidAppIdException, JsonProcessingException {
        AssertionExtensionInputs inputs = AssertionExtensionInputs.builder()
            .appid(new AppId("https://ubicua.com"))
                .build();
        assertNotNull(inputs);
        
        mapper = JacksonCodecs.json();
        String json = mapper.writeValueAsString(inputs);
        assertNotNull(json);
        
    }

    
}
