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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.upokecenter.cbor.CBORObject;
import ssido.authenticator.util.CryptoUtil;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.libsodium.jni.NaCl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ssido.authenticator.AttestationObject;
import ssido.authenticator.AttestationStatement;
import ssido.authenticator.Authenticator;
import ssido.authenticator.AuthenticatorCodec;
import ssido.authenticator.AuthenticatorData;

/**
 *
 * @author Andrei
 */
public class AuthenticatorTest {
    
    private static final Logger LOG = LoggerFactory.getLogger(Authenticator.class);

    static byte[] publicKey;
    static byte[] privateKey;
    static byte[] clientData;
    static byte[] rpId;
    
    public AuthenticatorTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
        
        NaCl.sodium();
        
        publicKey  = CryptoUtil.fromHex("f10645012f49752b451c604d2057893f485b30a19a0bc3b4404bc969859874cb");
        privateKey = CryptoUtil.fromHex("8f243ae3ee3218dcff652c1971215da45e69018514a49c38afd953d8e3169edff10645012f49752b451c604d2057893f485b30a19a0bc3b4404bc969859874cb");
        clientData = "Caracola".getBytes();
        rpId = Base64.getUrlDecoder().decode("request1");
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
     * Test of builder method, of class Authenticator.
     */
    @Test
    public void testBuilder() {
        Authenticator validator = Authenticator.builder()
                .publicKey(publicKey)
                .rpId(rpId)
                .counter(0)
                .attestationStatement(privateKey, clientData)
                .build();
        
        AttestationObject attestationObject = validator.getAttestationObject();
        assertNotNull(attestationObject);
    }

    /**
     * Test of getAttestationStatement method, of class Authenticator.
     * @throws java.io.IOException
     * @throws java.security.InvalidKeyException
     * @throws java.security.SignatureException
     * @throws java.security.NoSuchAlgorithmException
     */
    @Test
    public void testGetAttestationStatement() throws IOException, InvalidKeyException, SignatureException, NoSuchAlgorithmException {
        
        Authenticator validator = Authenticator.builder()
                .publicKey(publicKey)
                .rpId(rpId)
                .counter(0)
                .attestationStatement(privateKey, clientData)
                .build();
        
        AuthenticatorData validatorData = validator.getAuthenticatorData();
        AttestationStatement attestationStatement = validator.getAttestationStatement();
        
        ObjectNode result = attestationStatement.getObjectNode();
        JsonNode node = result.get("sig");
        byte[] sig = node.binaryValue();
        
        byte[] data = CryptoUtil.concat(validatorData.getBytes(), CryptoUtil.sha256(clientData));
        
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("Ed25519");
        Signature signature = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
        PublicKey pk = new EdDSAPublicKey(new EdDSAPublicKeySpec(publicKey, spec));
        byte[] encoded = AuthenticatorCodec.publicKeyToCose(pk);
        
        CBORObject cose = CBORObject.DecodeFromBytes(encoded);
        pk = AuthenticatorCodec.coseToPublicKey(cose);
        signature.initVerify(pk);
        signature.update(data);
        assertTrue(signature.verify(sig));
    }

    /**
     * Test of getAttestationObject method, of class Authenticator.
     * @throws java.io.IOException
     */
    @Test
    public void testGetAttestationObject() throws IOException {
        Authenticator validator = Authenticator.builder()
                .publicKey(publicKey)
                .rpId(rpId)
                .counter(0)
                .attestationStatement(privateKey, clientData)
                .build();
        
        AttestationObject attestationObject = validator.getAttestationObject();
        LOG.debug("Attestation object: {}", Base64.getUrlEncoder().withoutPadding().encodeToString(attestationObject.getBytes()));
        assertNotNull(attestationObject);
    }
}
