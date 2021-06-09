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
package ssido.core.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.net.URL;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Used to supply additional Relying Party attributes when creating a new credential.
 *
 * @see <a href="https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialrpentity">§5.4.2. Relying
 * Party Parameters for Credential Generation (dictionary PublicKeyCredentialRpEntity)
 * </a>
 */
public final class RelyingPartyIdentity implements PublicKeyCredentialEntity {
    /**
     * The human-palatable name of the Relaying Party.
     *
     * <p>
     * For example: "ACME Corporation", "Wonderful Widgets, Inc." or "ОАО Примертех".
     * </p>
     */
    @Nonnull
    private final String name;
    /**
     * A unique identifier for the Relying Party, which sets the <a href="https://www.w3.org/TR/webauthn/#rp-id">RP
     * ID</a>.
     *
     * @see <a href="https://www.w3.org/TR/webauthn/#rp-id">RP ID</a>
     */
    @Nonnull
    private final String id;
    /**
     * A URL which resolves to an image associated with the entity. For example, this could be the Relying Party's
     * logo.
     *
     * <p>This URL MUST be an a priori authenticated URL. Authenticators MUST accept and store a
     * 128-byte minimum length for an icon member’s value. Authenticators MAY ignore an icon member’s value if its
     * length is greater than 128 bytes. The URL’s scheme MAY be "data" to avoid fetches of the URL, at the cost of
     * needing more storage.
     * </p>
     */
    @Nonnull
    private final Optional<URL> icon;

    @JsonCreator
    private RelyingPartyIdentity(@Nonnull @JsonProperty("name") String name, @Nonnull @JsonProperty("id") String id, @JsonProperty("icon") URL icon) {
        this(name, id, Optional.ofNullable(icon));
    }

    public static RelyingPartyIdentityBuilder.MandatoryStages builder() {
        return new RelyingPartyIdentityBuilder.MandatoryStages();
    }


    public static class RelyingPartyIdentityBuilder {
        private String name;
        private String id;
        @Nonnull
        private Optional<URL> icon = Optional.empty();

        public static class MandatoryStages {
            private RelyingPartyIdentityBuilder builder = new RelyingPartyIdentityBuilder();

            public StageId id(String id) {
                builder.id(id);
                return new StageId();
            }


            public class StageId {
                public RelyingPartyIdentityBuilder name(String name) {
                    return builder.name(name);
                }
            }
        }

        /**
         * A URL which resolves to an image associated with the entity. For example, this could be the Relying Party's
         * logo.
         *
         * <p>This URL MUST be an a priori authenticated URL. Authenticators MUST accept and store a
         * 128-byte minimum length for an icon member’s value. Authenticators MAY ignore an icon member’s value if its
         * length is greater than 128 bytes. The URL’s scheme MAY be "data" to avoid fetches of the URL, at the cost of
         * needing more storage.
         * </p>
         * @param icon
         * @return 
         */
        public RelyingPartyIdentityBuilder icon(@Nonnull Optional<URL> icon) {
            this.icon = icon;
            return this;
        }

        /**
         * A URL which resolves to an image associated with the entity. For example, this could be the Relying Party's
         * logo.
         *
         * <p>This URL MUST be an a priori authenticated URL. Authenticators MUST accept and store a
         * 128-byte minimum length for an icon member’s value. Authenticators MAY ignore an icon member’s value if its
         * length is greater than 128 bytes. The URL’s scheme MAY be "data" to avoid fetches of the URL, at the cost of
         * needing more storage.
         * </p>
         * @param icon
         * @return 
         */
        public RelyingPartyIdentityBuilder icon(@Nonnull URL icon) {
            return this.icon(Optional.of(icon));
        }

        RelyingPartyIdentityBuilder() {
        }

        /**
         * The human-palatable name of the Relaying Party.
         *
         * <p>
         * For example: "ACME Corporation", "Wonderful Widgets, Inc." or "ОАО Примертех".
         * </p>
         * @param name
         * @return 
         */
        public RelyingPartyIdentityBuilder name(@Nonnull final String name) {
            this.name = name;
            return this;
        }

        /**
         * A unique identifier for the Relying Party, which sets the <a href="https://www.w3.org/TR/webauthn/#rp-id">RP
         * ID</a>.
         *
         * @param id
         * @return 
         * @see <a href="https://www.w3.org/TR/webauthn/#rp-id">RP ID</a>
         */
        public RelyingPartyIdentityBuilder id(@Nonnull final String id) {
            this.id = id;
            return this;
        }

        public RelyingPartyIdentity build() {
            return new RelyingPartyIdentity(name, id, icon);
        }
    }

    public RelyingPartyIdentityBuilder toBuilder() {
        return new RelyingPartyIdentityBuilder().name(this.name).id(this.id).icon(this.icon);
    }

    /**
     * A unique identifier for the Relying Party, which sets the <a href="https://www.w3.org/TR/webauthn/#rp-id">RP
     * ID</a>.

     *
     * @return
     * @see <a href="https://www.w3.org/TR/webauthn/#rp-id">RP ID</a>
     */
    @Nonnull
    public String getId() {
        return this.id;
    }

   
    private RelyingPartyIdentity(@Nonnull final String name, @Nonnull final String id, @Nonnull final Optional<URL> icon) {
        this.name = name;
        this.id = id;
        this.icon = icon;
    }

    /**
     * The human-palatable name of the Relaying Party.
     *
     * <p>
     * For example: "ACME Corporation", "Wonderful Widgets, Inc." or "ОАО Примертех".
     * </p>
     */
    @Override
    @Nonnull
    public String getName() {
        return this.name;
    }

    /**
     * A URL which resolves to an image associated with the entity. For example, this could be the Relying Party's
     * logo.
     *
     * <p>This URL MUST be an a priori authenticated URL. Authenticators MUST accept and store a
     * 128-byte minimum length for an icon member’s value. Authenticators MAY ignore an icon member’s value if its
     * length is greater than 128 bytes. The URL’s scheme MAY be "data" to avoid fetches of the URL, at the cost of
     * needing more storage.
     * </p>
     */
    @Override
    @Nonnull
    public Optional<URL> getIcon() {
        return this.icon;
    }
    
    @Override
    public String toString(){
        return String.format("Relying Party [ id: %s, name: %s]", id, name);
    }
}
