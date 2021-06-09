package org.libsodium.jni;

/**
 *
 * @author ITON Solutions
 */
public class NaCl {

    static {
        System.loadLibrary("sodiumjni");
    }

    public static Sodium sodium() {
        Sodium.sodium_init();
        return SodiumHolder.SODIUM_INSTANCE;
    }
    
    private static final class SodiumHolder {
        public static final Sodium SODIUM_INSTANCE = new Sodium();
    }
    
    private NaCl() {
    }
}
