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

import com.fasterxml.jackson.databind.ObjectMapper;
import ssido.data.RegistrationRequest;
import ssido.util.JacksonCodecs;
import java.io.IOException;
import static org.junit.Assert.assertNotNull;
import org.junit.Test;

/**
 *
 * @author ITON Solutions
 */
public class RegistrationDataTest {
    
    @Test
    public void testRegistrationRequest() throws IOException  {
        String data = "{\"username\":\"Xrt39y\",\"credentialNickname\":\"Xrt39y\",\"requestId\":\"bRmodAUYRbndZCXAZe2vQVjgXEXt_d-EGRV4QjTQ8bE\",\"publicKeyCredentialCreationOptions\":{\"rp\":{\"name\":\"UBICUA WebAuthn demo\",\"id\":\"localhost\"},\"user\":{\"name\":\"Xrt39y\",\"displayName\":\"Xrt39y\",\"id\":\"ObyZ2TyDy1glX-DZFEnJDgr4UCqi3JH0Lt-knG6jRHU\"},\"challenge\":\"zSB9-9Vpha1Gdu4L5dUpdlWn1N6OeNj6d5DhD2iAdTs\",\"pubKeyCredParams\":[{\"alg\":-7,\"type\":\"public-key\"},{\"alg\":-8,\"type\":\"public-key\"},{\"alg\":-257,\"type\":\"public-key\"}],\"excludeCredentials\":[],\"authenticatorSelection\":{\"requireResidentKey\":false,\"userVerification\":\"preferred\"},\"attestation\":\"direct\",\"extensions\":{}}}";
        ObjectMapper mapper = JacksonCodecs.json();
        RegistrationRequest request = mapper.readValue(data, RegistrationRequest.class);
        assertNotNull(request);
    }

}
