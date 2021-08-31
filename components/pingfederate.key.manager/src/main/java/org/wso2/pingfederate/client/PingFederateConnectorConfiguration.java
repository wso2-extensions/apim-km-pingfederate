/*
 *  Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.pingfederate.client;

import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.apimgt.api.model.ConfigurationDto;
import org.wso2.carbon.apimgt.api.model.KeyManagerConnectorConfiguration;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Connector configuration for PingFederate.
 */
@Component(
        name = "pingfederate.configuration.component",
        immediate = true,
        service = KeyManagerConnectorConfiguration.class
)
public class PingFederateConnectorConfiguration implements KeyManagerConnectorConfiguration {

    @Override
    public String getImplementation() {

        return PingFederatKeyManagerClient.class.getName();
    }

    @Override
    public String getJWTValidator() {

        return PingFederateJWTValidatorImpl.class.getName();
    }

    @Override
    public List<ConfigurationDto> getConnectionConfigurations() {

        List<ConfigurationDto> configurationDtoList = new ArrayList<>();
        configurationDtoList
                .add(new ConfigurationDto(PingFederateConstants.USERNAME, "Username",
                        "input", "Username of admin user", "", true,
                        false, Collections.emptyList(), false));
        configurationDtoList
                .add(new ConfigurationDto(PingFederateConstants.PASSWORD, "Password",
                        "input", "Password of Admin user", "", true,
                        true, Collections.emptyList(), false));
        configurationDtoList
                .add(new ConfigurationDto(PingFederateConstants.TOKEN_VALIDATION_CLIENT_ID, "Client ID",
                        "input", "Client Id for Token Validation", "", true,
                        false, Collections.emptyList(), false));
        configurationDtoList
                .add(new ConfigurationDto(PingFederateConstants.TOKEN_VALIDATION_CLIENT_SECRET, "Client Secret",
                        "input", "Client Secret for Token Validation", "", true,
                        true, Collections.emptyList(), false));
        return configurationDtoList;
    }

    @Override
    public List<ConfigurationDto> getApplicationConfigurations() {

        List<ConfigurationDto> configurationDtoList = new ArrayList<>();
        configurationDtoList
                .add(new ConfigurationDto(PingFederateConstants.BYPASS_APPROVAL_PAGES,
                        "Bypass Approval Pages", "select",
                        "Enable to skip authorization approval pages",
                        "false",
                        false, false,
                        Arrays.asList("false", "true"), false));
        configurationDtoList
                .add(new ConfigurationDto(PingFederateConstants.RESTRICT_RESPONSE_TYPES,
                        "Restricted Response Types", "select",
                        "Select Response Types Client can request",
                        "" ,
                        false, false,
                        Arrays.asList("code", "token", "id_token", "code token", "code id_token", "token id_token",
                                "code token id_token"), true));
        configurationDtoList
                .add(new ConfigurationDto(PingFederateConstants.CLIENT_AUTHENTICATION_TYPE,
                        "Client Authentication Type", "select",
                        "Select the OAuth Client Authentication Type",
                        "SECRET",
                        false, false,
                        Arrays.asList("NONE", "SECRET", "CLIENT_CERT", "PRIVATE_KEY_JWT"), false));
        configurationDtoList
                .add(new ConfigurationDto(PingFederateConstants.RESTRICTED_SCOPES,
                        "Restricted Scopes", "input",
                        "Add available scopes that the client can request",
                        "",
                        false, false,
                        Collections.emptyList(), false));
        return configurationDtoList;
    }

    @Override
    public String getType() {

        return PingFederateConstants.PING_FEDERATE_TYPE;
    }

    @Override
    public String getDisplayName() {

        return PingFederateConstants.DISPLAY_NAME;
    }

    @Override
    public String getDefaultConsumerKeyClaim() {

        return PingFederateConstants.CONSUMER_KEY_CLAIM;
    }
}
