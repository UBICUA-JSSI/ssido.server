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

package ssido.attestation.resolver;

import ssido.util.CollectionUtil;
import ssido.attestation.TrustResolver;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

/**
 * A {@link TrustResolver} whose {@link #resolveTrustAnchor(X509Certificate,
 * List)} method calls {@link TrustResolver#resolveTrustAnchor(X509Certificate,
 * List)} on each of the subordinate {@link TrustResolver}s in turn, and
 * returns the first non-<code>null</code> result.
 */
public final class CompositeTrustResolver implements TrustResolver {

    private final List<TrustResolver> resolvers;

    public CompositeTrustResolver(List<TrustResolver> resolvers) {
        this.resolvers = CollectionUtil.immutableList(resolvers);
    }

    @Override
    public Optional<X509Certificate> resolveTrustAnchor(X509Certificate attestationCertificate, List<X509Certificate> certificateChain) {
        for (TrustResolver resolver : resolvers) {
            Optional<X509Certificate> result = resolver.resolveTrustAnchor(attestationCertificate, certificateChain);
            if (result.isPresent()) {
                return result;
            }
        }
        return Optional.empty();
    }
}
