/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ssido.cose;

import ssido.cose.AlgorithmID;
import ssido.cose.OneKey;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
public class OneKeyTest {
    
    public OneKeyTest() {
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
     * Test of add method, of class OneKey.
     */
    @Test
    public void testAdd_KeyKeys_CBORObject() {

    }

    /**
     * Test of add method, of class OneKey.
     */
    @Test
    public void testAdd_CBORObject_CBORObject() {

    }

    /**
     * Test of get method, of class OneKey.
     */
    @Test
    public void testGet_KeyKeys() {

    }

    /**
     * Test of get method, of class OneKey.
     * @throws java.lang.Exception
     */
    @Test
    public void testGet_CBORObject() throws Exception {

    }

    /**
     * Test of HasAlgorithmID method, of class OneKey.
     */
    @Test
    public void testHasAlgorithmID() {
 
    }

    /**
     * Test of HasKeyID method, of class OneKey.
     */
    @Test
    public void testHasKeyID() {

    }

    /**
     * Test of HasKeyType method, of class OneKey.
     */
    @Test
    public void testHasKeyType() {

    }

    /**
     * Test of HasKeyOp method, of class OneKey.
     */
    @Test
    public void testHasKeyOp() {

    }

    /**
     * Test of GetCurve2 method, of class OneKey.
     * @throws java.lang.Exception
     */
    @Test
    public void testGetCurve2() throws Exception {

    }

    /**
     * Test of generateKey method, of class OneKey.
     * @throws java.lang.Exception
     */
    @Test
    public void testGenerateKey_AlgorithmID() throws Exception {

    }

    /**
     * Test of generateKey method, of class OneKey.
     * @throws java.lang.Exception
     */
    @Test
    public void testGenerateKey_CBORObject() throws Exception {

    }

    /**
     * Test of PublicKey method, of class OneKey.
     */
    @Test
    public void testPublicKey() {

    }

    /**
     * Test of EncodeToBytes method, of class OneKey.
     */
    @Test
    public void testEncodeToBytes() {

    }

    /**
     * Test of AsCBOR method, of class OneKey.
     */
    @Test
    public void testAsCBOR() {

    }

    /**
     * Test of AsPublicKey method, of class OneKey.
     * @throws java.lang.Exception
     */
    @Test
    public void testAsPublicKey() throws Exception {
        OneKey instance = OneKey.generateKey(AlgorithmID.ECDSA_256);
        PublicKey result = instance.AsPublicKey();
        assertEquals(result.getAlgorithm(), "EC");
        assertEquals(result.getFormat(), "X.509");
        
        byte[] rgbSPKI = result.getEncoded();
        String f =  toHex(rgbSPKI);
        assertEquals(rgbSPKI.length, 91);
        
        KeyFactory factory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(rgbSPKI);
        PublicKey pubKey = (PublicKey) factory.generatePublic(spec);
        assertNotNull(pubKey);
    }

    /**
     * Test of AsPrivateKey method, of class OneKey.
     * @throws java.lang.Exception
     */
    @Test
    public void testAsPrivateKey() throws Exception {
        OneKey instance = OneKey.generateKey(AlgorithmID.ECDSA_256);
        PrivateKey result = instance.AsPrivateKey();
        
        assertEquals(result.getAlgorithm(), "EC");
        assertEquals(result.getFormat(), "PKCS#8");
        
        byte[] rgbPrivate = result.getEncoded();
        String x = toHex(rgbPrivate);
        
        KeyPairGenerator kpgen = KeyPairGenerator.getInstance("EC");
        KeyFactory kFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(rgbPrivate);
        PrivateKey privKey = (PrivateKey) kFactory.generatePrivate(spec);
        assertNotNull(privKey);
    }

    /**
     * Test of getUserData method, of class OneKey.
     */
    @Test
    public void testGetUserData() {

    }

    /**
     * Test of setUserData method, of class OneKey.
     */
    @Test
    public void testSetUserData() {

    }

    /**
     * Test of GetCurve method, of class OneKey.
     * @throws java.lang.Exception
     */
    @Test
    public void testGetCurve() throws Exception {

    }
    
    static String toHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for (byte b : a) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
