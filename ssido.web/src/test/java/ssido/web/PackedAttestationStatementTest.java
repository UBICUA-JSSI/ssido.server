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
import java.security.spec.InvalidKeySpecException;
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
import org.libsodium.jni.SodiumException;
import ssido.authenticator.AttestationStatement;
import ssido.authenticator.AuthenticatorCodec;
import ssido.authenticator.PackedAttestationStatement;

/**
 *
 * @author Andrei
 */
public class PackedAttestationStatementTest {
    
    public PackedAttestationStatementTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
        NaCl.sodium();
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

    @Test
    public void testPackedAttestationStatement() throws SodiumException, IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException {
        
        byte[] publicKeyByte  = CryptoUtil.fromHex("f10645012f49752b451c604d2057893f485b30a19a0bc3b4404bc969859874cb");
        byte[] privateKeyByte = CryptoUtil.fromHex("8f243ae3ee3218dcff652c1971215da45e69018514a49c38afd953d8e3169edff10645012f49752b451c604d2057893f485b30a19a0bc3b4404bc969859874cb");
        byte[] authenticatorData = "Hola ".getBytes();
        byte[] clientData = "Caracola".getBytes();
        
        AttestationStatement statement = PackedAttestationStatement.builder()
                .authenticatorData(authenticatorData)
                .clientData(clientData)
                .privateKey(privateKeyByte).build();
        
        ObjectNode result = statement.getObjectNode();
        JsonNode node = result.get("sig");
        byte[] sig = node.binaryValue();
        
        byte[] data = CryptoUtil.concat(authenticatorData, CryptoUtil.sha256(clientData));
        
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("Ed25519");
        Signature signature = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
        PublicKey publicKey = new EdDSAPublicKey(new EdDSAPublicKeySpec(publicKeyByte, spec));
        byte[] encoded = AuthenticatorCodec.publicKeyToCose(publicKey);
        
        CBORObject cose = CBORObject.DecodeFromBytes(encoded);
        publicKey = AuthenticatorCodec.coseToPublicKey(cose);
        signature.initVerify(publicKey);
        signature.update(data);
        assertTrue(signature.verify(sig));
    }
}
