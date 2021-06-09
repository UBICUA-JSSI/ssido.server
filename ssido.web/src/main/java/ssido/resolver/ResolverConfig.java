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

import java.io.Serializable;
import javax.enterprise.context.ApplicationScoped;
import org.apache.commons.configuration2.Configuration;
import org.apache.commons.configuration2.FileBasedConfiguration;
import org.apache.commons.configuration2.PropertiesConfiguration;
import org.apache.commons.configuration2.builder.FileBasedConfigurationBuilder;
import org.apache.commons.configuration2.builder.fluent.Parameters;
import org.apache.commons.configuration2.builder.fluent.PropertiesBuilderParameters;
import org.apache.commons.configuration2.ex.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author UBICUA
 */
@ApplicationScoped
public class ResolverConfig implements Serializable{
    
    private static final Logger LOG = LoggerFactory.getLogger(ResolverConfig.class);
    
    private Configuration config = null;
    
    private final FileBasedConfigurationBuilder<FileBasedConfiguration> builder
            = new FileBasedConfigurationBuilder<>(PropertiesConfiguration.class);
    
    public ResolverConfig(){
        init();
    }
    
    public void init(){
        LOG.debug(String.format("Configure from properties: %s", "ssido.properties"));
        
        PropertiesBuilderParameters properties = new Parameters().properties();
        properties.setPath("ssido.properties");
        builder.configure(properties);
        
        try {
            config = builder.getConfiguration();
        } catch (ConfigurationException ex) {
            LOG.error(String.format("Configuration error: %s", ex.getMessage()));
        }
    }
    
    public String getResolverUri(){
        return config.getString("resolver.uri");
    }
    
    public String getPropertiesUri(){
        return config.getString("properties.uri");
    }
    
}
