package foundation.identity.jsonld;

import com.apicatalog.jsonld.api.JsonLdError;
import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;
import com.apicatalog.jsonld.loader.FileLoader;
import com.apicatalog.jsonld.loader.HttpLoader;

import java.net.URI;
import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ConfigurableDocumentLoader implements DocumentLoader {

    private HttpClient httpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
    private DocumentLoader httpLoader = new HttpLoader(this.httpClient);
    private DocumentLoader fileLoader = new FileLoader();

    private boolean enableLocalCache = true;
    private boolean enableHttp = false;
    private boolean enableHttps = false;
    private boolean enableFile = false;

    private Map<URI, JsonDocument> localCache = new HashMap<URI, JsonDocument> ();
    private List<URI> httpContexts = new ArrayList<URI>();
    private List<URI> httpsContexts = new ArrayList<URI>();
    private List<URI> fileContexts = new ArrayList<URI>();

    public ConfigurableDocumentLoader() {

    }

    public ConfigurableDocumentLoader(Map<URI, JsonDocument> localCache) {
        if (localCache == null) throw new NullPointerException();
        this.localCache = localCache;
    }

    @Override
    public Document loadDocument(URI url, DocumentLoaderOptions options) throws JsonLdError {

        if (this.enableLocalCache) {
            return this.localCache.get(url);
        }
        if (enableHttp && "http".equals(url.getScheme().toLowerCase())) {
            if (this.httpContexts.isEmpty() || this.httpContexts.contains(url))
                return this.httpLoader.loadDocument(url, options);
        }
        if (enableHttps && "https".equals(url.getScheme().toLowerCase())) {
            if (this.httpsContexts.isEmpty() || this.httpsContexts.contains(url))
                return this.httpLoader.loadDocument(url, options);
        }
        if (enableFile && "file".equals(url.getScheme().toLowerCase())) {
            if (this.fileContexts.isEmpty() || this.fileContexts.contains(url))
                return this.fileLoader.loadDocument(url, options);
        }
        return null;
    }

    /*
     * Getters and setters
     */

    public HttpClient getHttpClient() {
        return this.httpClient;
    }

    public void setHttpClient(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public DocumentLoader getHttpLoader() {
        return this.httpLoader;
    }

    public void setHttpLoader(DocumentLoader httpLoader) {
        this.httpLoader = httpLoader;
    }

    public DocumentLoader getFileLoader() {
        return this.fileLoader;
    }

    public void setFileLoader(DocumentLoader fileLoader) {
        this.fileLoader = fileLoader;
    }

    public boolean isEnableLocalCache() {
        return this.enableLocalCache;
    }

    public void setEnableLocalCache(boolean enableLocalCache) {
        this.enableLocalCache = enableLocalCache;
    }

    public boolean isEnableHttp() {
        return this.enableHttp;
    }

    public void setEnableHttp(boolean enableHttp) {
        this.enableHttp = enableHttp;
    }

    public boolean isEnableHttps() {
        return this.enableHttps;
    }

    public void setEnableHttps(boolean enableHttps) {
        this.enableHttps = enableHttps;
    }

    public boolean isEnableFile() {
        return this.enableFile;
    }

    public void setEnableFile(boolean enableFile) {
        this.enableFile = enableFile;
    }

    public Map<URI, JsonDocument> getLocalCache() {
        return this.localCache;
    }

    public void setLocalCache(Map<URI, JsonDocument> localCache) {
        this.localCache = localCache;
    }

    public List<URI> getHttpContexts() {
        return this.httpContexts;
    }

    public void setHttpContexts(List<URI> httpContexts) {
        this.httpContexts = httpContexts;
    }

    public List<URI> getHttpsContexts() {
        return this.httpsContexts;
    }

    public void setHttpsContexts(List<URI> httpsContexts) {
        this.httpsContexts = httpsContexts;
    }

    public List<URI> getFileContexts() {
        return this.fileContexts;
    }

    public void setFileContexts(List<URI> fileContexts) {
        this.fileContexts = fileContexts;
    }
}
