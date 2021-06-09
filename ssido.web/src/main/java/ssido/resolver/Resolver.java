/*
 * Copyright 2021 UBICUA.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ssido.resolver;

/**
 *
 * @author UBICUA
 */
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.Map;

import org.apache.http.HttpEntity;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

import uniresolver.ResolutionException;
import uniresolver.UniResolver;
import uniresolver.result.ResolveResult;

public class Resolver implements UniResolver {

    private static final Logger LOG = LoggerFactory.getLogger(Resolver.class);

    private static Resolver INSTANCE;
    private static final ObjectMapper mapper = new ObjectMapper();
    private static final ResolverConfig config = new ResolverConfig();
    
    private HttpClient HTTP_CLIENT = HttpClients.createDefault();

    private URI resolveUri;
    private URI propertiesUri;

    private Resolver() {
        this.resolveUri = URI.create(config.getResolverUri());
        this.propertiesUri = URI.create(config.getPropertiesUri());
    }
    
    public static Resolver getInstance(){
        if(INSTANCE == null){
            INSTANCE = new Resolver();
        }
        return INSTANCE;
    }

    @Override
    public ResolveResult resolve(String identifier) throws ResolutionException {
        return resolve(identifier, null);
    }

    @Override
    public ResolveResult resolve(String identifier, Map<String, String> options) throws ResolutionException {
        if (identifier == null) {
            throw new NullPointerException();
        }

        // encode identifier
        String encodedIdentifier;

        try {
            encodedIdentifier = URLEncoder.encode(identifier, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            throw new ResolutionException(ex.getMessage(), ex);
        }

        // prepare HTTP request
        String uriString = getResolveUri().toString();
        if (!uriString.endsWith("/")) {
            uriString += "/";
        }
        uriString += encodedIdentifier;

        HttpGet httpGet = new HttpGet(URI.create(uriString));
        // execute HTTP request
        ResolveResult resolveResult;

        if (LOG.isDebugEnabled()) {
            LOG.debug("Request for identifier " + identifier + " to: " + uriString);
        }

        try ( CloseableHttpResponse httpResponse = (CloseableHttpResponse) this.getHttpClient().execute(httpGet)) {

            int statusCode = httpResponse.getStatusLine().getStatusCode();
            String statusMessage = httpResponse.getStatusLine().getReasonPhrase();

            if (LOG.isDebugEnabled()) {
                LOG.debug("Response status from " + uriString + ": " + statusCode + " " + statusMessage);
            }

            if (statusCode == 404) {
                return null;
            }

            HttpEntity httpEntity = httpResponse.getEntity();
            String httpBody = EntityUtils.toString(httpEntity);
            EntityUtils.consume(httpEntity);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Response body from " + uriString + ": " + httpBody);
            }

            if (httpResponse.getStatusLine().getStatusCode() > 200) {
                if (LOG.isWarnEnabled()) {
                    LOG.warn("Cannot retrieve RESOLVE RESULT for " + identifier + " from " + uriString + ": " + httpBody);
                }
                throw new ResolutionException(httpBody);
            }

            resolveResult = ResolveResult.fromJson(httpBody);
        } catch (IOException ex) {
            throw new ResolutionException("Cannot retrieve RESOLVE RESULT for " + identifier + " from " + uriString + ": " + ex.getMessage(), ex);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Retrieved RESOLVE RESULT for " + identifier + " (" + uriString + "): " + resolveResult);
        }
        // done
        return resolveResult;
    }

    @Override
    public Map<String, Map<String, Object>> properties() throws ResolutionException {

        // prepare HTTP request
        String uriString = this.getPropertiesUri().toString();

        HttpGet httpGet = new HttpGet(URI.create(uriString));
        httpGet.addHeader("Accept", UniResolver.PROPERTIES_MIME_TYPE);

        // execute HTTP request
        Map<String, Map<String, Object>> properties;

        if (LOG.isDebugEnabled()) {
            LOG.debug("Request to: " + uriString);
        }

        try ( CloseableHttpResponse httpResponse = (CloseableHttpResponse) this.getHttpClient().execute(httpGet)) {

            int statusCode = httpResponse.getStatusLine().getStatusCode();
            String statusMessage = httpResponse.getStatusLine().getReasonPhrase();

            if (LOG.isDebugEnabled()) {
                LOG.debug("Response status from " + uriString + ": " + statusCode + " " + statusMessage);
            }

            if (httpResponse.getStatusLine().getStatusCode() == 404) {
                return null;
            }

            HttpEntity httpEntity = httpResponse.getEntity();
            String httpBody = EntityUtils.toString(httpEntity);
            EntityUtils.consume(httpEntity);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Response body from " + uriString + ": " + httpBody);
            }

            if (httpResponse.getStatusLine().getStatusCode() > 200) {
                if (LOG.isWarnEnabled()) {
                    LOG.warn("Cannot retrieve DRIVER PROPERTIES from " + uriString + ": " + httpBody);
                }
                throw new ResolutionException(httpBody);
            }

            properties = (Map<String, Map<String, Object>>) mapper.readValue(httpBody, Map.class);
        } catch (IOException ex) {
            throw new ResolutionException("Cannot retrieve DRIVER PROPERTIES from " + uriString + ": " + ex.getMessage(), ex);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Retrieved DRIVER PROPERTIES (" + uriString + "): " + properties);
        }
        // done
        return properties;
    }

    /*
     * Getters and setters
     */
    public HttpClient getHttpClient() {
        return this.HTTP_CLIENT;
    }

    public void setHttpClient(HttpClient httpClient) {
        this.HTTP_CLIENT = httpClient;
    }

    public URI getResolveUri() {
        return this.resolveUri;
    }

    public void setResolveUri(URI resolveUri) {
        this.resolveUri = resolveUri;
    }

    public void setResolveUri(String resolveUri) {
        this.resolveUri = URI.create(resolveUri);
    }

    public URI getPropertiesUri() {
        return this.propertiesUri;
    }

    public void setPropertiesUri(URI propertiesUri) {
        this.propertiesUri = propertiesUri;
    }

    public void setPropertiesUri(String propertiesUri) {
        this.propertiesUri = URI.create(propertiesUri);
    }
}
