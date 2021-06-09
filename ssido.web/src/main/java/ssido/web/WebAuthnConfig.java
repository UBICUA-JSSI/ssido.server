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

package ssido.web;

import ssido.util.CollectionUtil;
import ssido.core.data.RelyingPartyIdentity;
import ssido.core.extension.appid.AppId;
import ssido.core.extension.appid.InvalidAppIdException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class WebAuthnConfig {

    private static final Logger LOG = LoggerFactory.getLogger(WebAuthnConfig.class);

//    public static final String REGISTER = "wss://176.84.169.249:8443/ssido/register";
//    public static final String AUTHENTICATE = "wss://176.84.169.249:8443/ssido/authenticate";
    
    public static final String REGISTER = "wss://5.9.131.154:8443/ssido/register";
    public static final String AUTHENTICATE = "wss://5.9.131.154:8443/ssido/authenticate";
    
    
    private static final RelyingPartyIdentity DEFAULT_RP_ID = RelyingPartyIdentity.builder()
            .id("ubicua.com")
            .name("UBICUA SSIDO").build();

    private final Set<String> origins;
    private final RelyingPartyIdentity rpIdentity;
    private final Optional<AppId> appId;

    private WebAuthnConfig(Set<String> origins, RelyingPartyIdentity rpIdentity, Optional<AppId> appId) {
        this.origins = CollectionUtil.immutableSet(origins);
        this.rpIdentity = rpIdentity;
        this.appId = appId;
    }

    private static WebAuthnConfig instance;
    private static WebAuthnConfig getInstance() {
        if (instance == null) {
            try {
                instance = new WebAuthnConfig(computeOrigins(), computeRpIdentity(), computeAppId());
            } catch (MalformedURLException | InvalidAppIdException e) {
                throw new RuntimeException(e);
            }
        }
        return instance;
    }

    public static Set<String> getOrigins() {
        return getInstance().origins;
    }

    public static RelyingPartyIdentity getRpIdentity() {
        return getInstance().rpIdentity;
    }

    public static Optional<AppId> getAppId() {
        return getInstance().appId;
    }

    private static Set<String> computeOrigins() {
        final String origins = System.getenv("UBICUA_WEBAUTHN_ALLOWED_ORIGINS");

        LOG.debug("UBCUA_WEBAUTHN_ALLOWED_ORIGINS: {}", origins);

        final Set<String> result;

        if (origins == null) {
            result = new HashSet<>(Arrays.asList(new String[]{REGISTER, AUTHENTICATE}));
        } else {
            result = new HashSet<>(Arrays.asList(origins.split(",")));
        }

        LOG.info("Origins: {}", result);

        return result;
    }

    private static RelyingPartyIdentity computeRpIdentity() throws MalformedURLException {
        final String name = System.getenv("UBICUA_WEBAUTHN_RP_NAME");
        final String id = System.getenv("UBICUA_WEBAUTHN_RP_ID");
        final String icon = System.getenv("UBICUA_WEBAUTHN_RP_ICON");

        LOG.debug("RP name: {}", name);
        LOG.debug("RP ID: {}", id);
        LOG.debug("RP icon: {}", icon);

        RelyingPartyIdentity.RelyingPartyIdentityBuilder resultBuilder = DEFAULT_RP_ID.toBuilder();

        if (name == null) {
            LOG.debug("RP name not given - using default.");
        } else {
            resultBuilder.name(name);
        }

        if (id == null) {
            LOG.debug("RP ID not given - using default.");
        } else {
            resultBuilder.id(id);
        }

        if (icon == null) {
            LOG.debug("RP icon not given - using none.");
        } else {
            try {
            resultBuilder.icon(Optional.of(new URL(icon)));
            } catch (MalformedURLException e) {
                LOG.error("Invalid icon URL: {}", icon, e);
                throw e;
            }
        }

        final RelyingPartyIdentity result = resultBuilder.build();
        LOG.debug("RP identity: {}", result.toString());
        return result;
    }

    private static Optional<AppId> computeAppId() throws InvalidAppIdException {
        final String appId = System.getenv("UBICUA_WEBAUTHN_U2F_APPID");
        LOG.debug("UBICUA_WEBAUTHN_U2F_APPID: {}", appId);

        AppId result = appId == null
            ? new AppId("https://ubicua.com:8443")
            : new AppId(appId);

        LOG.debug("U2F AppId: {}", result.getId());
        return Optional.of(result);
    }

}
