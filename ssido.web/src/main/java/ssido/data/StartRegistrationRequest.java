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
import static ssido.web.WebAuthnConfig.REGISTER;

/**
 *
 * @author UBICUA
 */
public class StartRegistrationRequest {

    @JsonProperty("success") final boolean success = true;
    @JsonProperty("request") RegistrationRequest request;
    @JsonProperty("action") String action = REGISTER + "/finish";

    @JsonCreator
    public StartRegistrationRequest(@JsonProperty("request") RegistrationRequest request) {
        this.request = request;
    }
}
