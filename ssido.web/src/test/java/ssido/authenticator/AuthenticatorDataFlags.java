// Copyright (c) 2018, Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
package ssido.authenticator;


/**
 * The flags bit field of an validator data structure, decoded as a high-level object.
 *
 * @see <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#flags">Table 1</a>
 */
public final class AuthenticatorDataFlags {
    private byte flag;
    /**
     * User present
     */
    public final boolean UP;
    /**
     * User verified
     */
    public final boolean UV;
    /**
     * Attested credential data present.
     *
     * <p>
     * Users of this library should not need to inspect this value directly.
     * </p>
     *
     * @see AuthenticatorData#getAttestedCredentialData()
     */
    public final boolean AT;
    /**
     * Extension data present.
     *
     * @see AuthenticatorData#getExtensions()
     */
    public final boolean ED;

    /**
     * Decode an {@link AuthenticatorDataFlags} object from a raw bit field byte.
     * @param value
     */
    private AuthenticatorDataFlags(byte flag) {
        this.flag = flag;
        UP = (flag & Bitmasks.UP) != 0;
        UV = (flag & Bitmasks.UV) != 0;
        AT = (flag & Bitmasks.AT) != 0;
        ED = (flag & Bitmasks.ED) != 0;
    }


    private static final class Bitmasks {
        static final byte UP = (byte) 0x01;
        static final byte UV = (byte) 0x04;
        static final byte AT = (byte) 0x40;
        static final byte ED = (byte) 0x80;
        /* Reserved bits */
        // final boolean RFU1 = (value & 0x02) > 0;
        // final boolean RFU2_1 = (value & 0x08) > 0;
        // final boolean RFU2_2 = (value & 0x10) > 0;
        // static final boolean RFU2_3 = (value & 0x20) > 0;
    }
    
    public static AuthenticatorDataFlagsBuilder builder() {
        return new AuthenticatorDataFlagsBuilder();
    }

    public static class AuthenticatorDataFlagsBuilder {
        private int flag = Bitmasks.AT | Bitmasks.UP;

        AuthenticatorDataFlagsBuilder() {
        }

        /**
         * The user is verified.
         * @param UV
         * @return 
         */
        public AuthenticatorDataFlagsBuilder verified(boolean UV) {
            flag |= Bitmasks.UV;
            return this;
        }

        /**
         * The Attested credential data present.
         * @param AT
         * @return 
         */
        public AuthenticatorDataFlagsBuilder attested(boolean AT) {
            flag |= Bitmasks.AT;
            return this;
        }

        /**
         * Extension data present.
         * @param ED
         * @return 
         */
        public AuthenticatorDataFlagsBuilder extension(boolean ED) {
            flag |= Bitmasks.ED;
            return this;
        }

        public AuthenticatorDataFlags build() {
            return new AuthenticatorDataFlags((byte) flag);
        }
    }
    
    public byte[] getBytes(){
        return new byte[]{flag};
    }
}
