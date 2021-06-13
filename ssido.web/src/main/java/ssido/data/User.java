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
package ssido.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 *
 * @author UBICUA
 */
public class User {
    
    String requestId;
    String username;
    String displayName;
    String did;

    @JsonCreator
    public User(
            @JsonProperty("requestId") String requestId, 
            @JsonProperty("username") String username, 
            @JsonProperty("displayName") String displayName, 
            @JsonProperty("did") String did) {
        
        this.requestId = requestId;
        this.username = username;
        this.displayName = displayName;
        this.did = did;
    }
    
    public String getRequestId() {
        return requestId;
    }

    public String getUsername() {
        return username;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDid() {
        return did;
    }
    
    @Override
    public String toString(){
        return String.format("Login {requestId = %s, username = %s, did = %s}", requestId, username, did);
    }

}
