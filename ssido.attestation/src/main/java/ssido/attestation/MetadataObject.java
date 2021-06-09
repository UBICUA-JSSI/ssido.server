// Copyright (c) 2015-2018, Yubico AB
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
package ssido.attestation;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableList;
import com.google.common.io.Closeables;
import ssido.util.CertificateParser;
import ssido.util.ExceptionUtil;
import ssido.util.JacksonCodecs;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@JsonIgnoreProperties(ignoreUnknown = true)
public final class MetadataObject {
    private static final Logger LOG = LoggerFactory.getLogger(MetadataObject.class);
    private static final ObjectMapper OBJECT_MAPPER = JacksonCodecs.json();

    private final transient JsonNode data;
    private final String identifier;
    private final long version;
    private final Map<String, String> vendorInfo;
    private final List<String> trustedCertificates;
    private final List<JsonNode> devices;

    @JsonCreator
    public MetadataObject(JsonNode data) {
        this.data = data;
        try {
            vendorInfo = OBJECT_MAPPER.readValue(data.get("vendorInfo").traverse(), new TypeReference<Map<String, String>>() {});
            devices = (List<JsonNode>) OBJECT_MAPPER.readValue(data.get("devices").traverse(), new TypeReference<List<JsonNode>>() {});
            trustedCertificates = OBJECT_MAPPER.readValue(data.get("trustedCertificates").traverse(), new TypeReference<List<String>>() {});
            
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid JSON data", e);
        }
        identifier = data.get("identifier").asText();
        version = data.get("version").asLong();
    }

    public static MetadataObject readDefault() {
        InputStream is = MetadataObject.class.getResourceAsStream("/metadata.json");
        try {
            return JacksonCodecs.json().readValue(is, MetadataObject.class);
        } catch (IOException e) {
            throw ExceptionUtil.wrapAndLog(LOG, "Failed to read default metadata", e);
        } finally {
            Closeables.closeQuietly(is);
        }
    }

    public String getIdentifier() {
        return identifier;
    }

    public long getVersion() {
        return version;
    }

    public Map<String, String> getVendorInfo() {
        return vendorInfo;
    }

    public List<String> getTrustedCertificates() {
        return trustedCertificates;
    }

    @JsonIgnore
    public List<X509Certificate> getParsedTrustedCertificates() throws CertificateException {
        List<X509Certificate> list = new ArrayList<>();
        for (String trustedCertificate : trustedCertificates) {
            X509Certificate x509Certificate = CertificateParser.parsePem(trustedCertificate);
            list.add(x509Certificate);
        }
        return list;
    }

    public List<JsonNode> getDevices() {
        return MoreObjects.firstNonNull(devices, ImmutableList.of());
    }

    @Override
    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof MetadataObject)) return false;
        final MetadataObject other = (MetadataObject) o;
        return !(this.data == null ? other.data != null : !this.data.equals(other.data));
    }

    @Override
    public int hashCode() {
        final int PRIME = 59;
        int result = 1;
        result = result * PRIME + (this.data == null ? 43 : this.data.hashCode());
        return result;
    }
}
