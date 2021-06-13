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


import ssido.core.data.ByteArray;
import ssido.core.data.PublicKeyCredentialRequestOptions;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Optional;
import javax.annotation.Nonnull;


/**
 * A combination of a {@link PublicKeyCredentialRequestOptions} and, optionally, a {@link #getUsername() username}.
 */
public final class AssertionRequest {
    /**
     * An object that can be serialized to JSON and passed as the <code>publicKey</code> argument to
     * <code>navigator.credentials.get()</code>.
     */
    @Nonnull
    private final PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;
    /**
     * The username of the user to authenticate, if the user has already been identified.
     * <p>
     * If this is absent, this indicates that this is a request for an assertion by a <a
     * href="https://www.w3.org/TR/webauthn/#client-side-resident-public-key-credential-source">client-side-resident
     * credential</a>, and identification of the user has been deferred until the response is received.
     * </p>
     */
    @Nonnull
    private final Optional<String> username;
    private final ByteArray requestId;

    @JsonCreator
    private AssertionRequest(
            @JsonProperty("requestId") @Nonnull ByteArray requestId,
            @JsonProperty("publicKeyCredentialRequestOptions") @Nonnull PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,
            @JsonProperty("username") String username) {
//        this(publicKeyCredentialRequestOptions, Optional.fromNullable(username));
        this.requestId = requestId;
        this.username = Optional.of(username);
        this.publicKeyCredentialRequestOptions = publicKeyCredentialRequestOptions;

    }

//    public static AssertionRequestBuilder.MandatoryStages builder() {
//        return new AssertionRequestBuilder.MandatoryStages();
//    }
//
//    public static class AssertionRequestBuilder {
//        private PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;
//        private Optional<String> username = Optional.absent();
//
//
//        public static class MandatoryStages {
//            private final AssertionRequestBuilder builder = new AssertionRequestBuilder();
//
//            /**
//             * {@link AssertionRequestBuilder#publicKeyCredentialRequestOptions(PublicKeyCredentialRequestOptions)
//             * publicKeyCredentialRequestOptions} is a required parameter.
//             * @param publicKeyCredentialRequestOptions
//             * @return
//             */
//            public AssertionRequestBuilder publicKeyCredentialRequestOptions(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions) {
//                return builder.publicKeyCredentialRequestOptions(publicKeyCredentialRequestOptions);
//            }
//        }
//
//        /**
//         * The username of the user to authenticate, if the user has already been identified.
//         * <p>
//         * If this is absent, this indicates that this is a request for an assertion by a <a
//         * href="https://www.w3.org/TR/webauthn/#client-side-resident-public-key-credential-source">client-side-resident
//         * credential</a>, and identification of the user has been deferred until the response is received.
//         * </p>
//         * @param username
//         * @return
//         */
//        public AssertionRequestBuilder username(@NonNull Optional<String> username) {
//            this.username = username;
//            return this;
//        }
//
//        /**
//         * The username of the user to authenticate, if the user has already been identified.
//         * <p>
//         * If this is absent, this indicates that this is a request for an assertion by a <a
//         * href="https://www.w3.org/TR/webauthn/#client-side-resident-public-key-credential-source">client-side-resident
//         * credential</a>, and identification of the user has been deferred until the response is received.
//         * </p>
//         * @param username
//         * @return
//         */
//        public AssertionRequestBuilder username(@NonNull String username) {
//            return this.username(Optional.of(username));
//        }
//
//        AssertionRequestBuilder() {
//        }
//
//        /**
//         * An object that can be serialized to JSON and passed as the <code>publicKey</code> argument to
//         * <code>navigator.credentials.get()</code>.
//         * @param publicKeyCredentialRequestOptions
//         * @return
//         */
//        public AssertionRequestBuilder publicKeyCredentialRequestOptions(@NonNull final PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions) {
//            this.publicKeyCredentialRequestOptions = publicKeyCredentialRequestOptions;
//            return this;
//        }
//
//        public AssertionRequest build() {
//            return new AssertionRequest(publicKeyCredentialRequestOptions, username);
//        }
//    }
//
//    public AssertionRequestBuilder toBuilder() {
//        return new AssertionRequestBuilder()
//                .publicKeyCredentialRequestOptions(this.publicKeyCredentialRequestOptions)
//                .username(this.username);
//    }

    /**
     * An object that can be serialized to JSON and passed as the <code>publicKey</code> argument to

     * <code>navigator.credentials.get()</code>.
     * @return 
     */
    @Nonnull
    public PublicKeyCredentialRequestOptions getPublicKeyCredentialRequestOptions() {
        return this.publicKeyCredentialRequestOptions;
    }

    public ByteArray getRequestId() {
        return requestId;
    }

    @Nonnull
    public Optional<String> getUsername() {
        return username;
    }
    //    /**
//     * The username of the user to authenticate, if the user has already been identified.
//     * <p>
//     * If this is absent, this indicates that this is a request for an assertion by a <a
//     * href="https://www.w3.org/TR/webauthn/#client-side-resident-public-key-credential-source">client-side-resident
//     * credential</a>, and identification of the user has been deferred until the response is received.
//     * </p>
//     * @return
//     */
//    @NonNull
//    public Optional<String> getUsername() {
//        return this.username;
//    }
//
//    private AssertionRequest(
//            @NonNull final PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,
//            @NonNull final Optional<String> username) {
//        this.publicKeyCredentialRequestOptions = publicKeyCredentialRequestOptions;
//        this.username = username;
//    }
}
