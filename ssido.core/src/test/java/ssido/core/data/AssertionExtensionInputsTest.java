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
