/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
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

import com.google.gson.Gson;
import feign.Feign;
import feign.Response;
import feign.auth.BasicAuthRequestInterceptor;
import feign.gson.GsonDecoder;
import feign.gson.GsonEncoder;
import feign.slf4j.Slf4jLogger;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpStatus;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.AccessTokenInfo;
import org.wso2.carbon.apimgt.api.model.AccessTokenRequest;
import org.wso2.carbon.apimgt.api.model.ApplicationConstants;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.api.model.OAuthAppRequest;
import org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo;
import org.wso2.carbon.apimgt.api.model.Scope;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.AbstractKeyManager;
import org.wso2.carbon.apimgt.impl.kmclient.ApacheFeignHttpClient;
import org.wso2.carbon.apimgt.impl.kmclient.FormEncoder;
import org.wso2.carbon.apimgt.impl.kmclient.KMClientErrorDecoder;
import org.wso2.carbon.apimgt.impl.kmclient.KeyManagerClientException;
import org.wso2.carbon.apimgt.impl.kmclient.model.AuthClient;
import org.wso2.carbon.apimgt.impl.kmclient.model.TokenInfo;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.pingfederate.model.ClientInfo;
import org.wso2.pingfederate.model.ClientInfoList;
import org.wso2.pingfederate.model.IntrospectClient;
import org.wso2.pingfederate.model.IntrospectInfo;
import org.wso2.pingfederate.model.PingFederateDCRClient;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * This class provides the implementation to use "pingFederate" for managing
 * OAuth clients and Tokens needed by WSO2 API Manager.
 */
public class PingFederatKeyManagerClient extends AbstractKeyManager {

    private static final Log log = LogFactory.getLog(PingFederatKeyManagerClient.class);
    private PingFederateDCRClient pingFederateDCRClient;
    private IntrospectClient introspectionClient;
    private String tokenEndpoint;
    private AuthClient authClient;

    @Override
    public OAuthApplicationInfo createApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {

        ClientInfo clientInfo = fromOauthAppRequestToClientInfo(oAuthAppRequest);

        Response response = pingFederateDCRClient.createApplication(toClientInfoList(clientInfo));
        if (response.status() == HttpStatus.SC_OK) {
            log.debug("Application created in PINGFederate");
            return fromClientInfoToOauthApplicationInfo(clientInfo);
        } else {
            throw new APIManagementException("Error while creating Oauth Application in PingFederate Server");
        }
    }

    /**
     * This method will create {@code OAuthApplicationInfo} object from a Map of Attributes.
     *
     * @param clientInfo Response returned from server as a Map
     * @return OAuthApplicationInfo object will return.
     */
    private OAuthApplicationInfo fromClientInfoToOauthApplicationInfo(ClientInfo clientInfo) {

        OAuthApplicationInfo appInfo = new OAuthApplicationInfo();
        appInfo.setClientName(clientInfo.getName());
        appInfo.setClientId(clientInfo.getClientId());
        appInfo.setClientSecret(clientInfo.getSecret());
        if (clientInfo.getRedirectUris() != null) {
            appInfo.setCallBackURL(String.join(",", clientInfo.getRedirectUris()));
        }

        if (clientInfo.getGrantTypes() != null) {
            appInfo.addParameter(APIConstants.JSON_GRANT_TYPES, String.join(" ", clientInfo.getGrantTypes()));
        }
        if (StringUtils.isNotEmpty(clientInfo.getName())) {
            appInfo.addParameter(ApplicationConstants.OAUTH_CLIENT_NAME, clientInfo.getName());
        }
        if (StringUtils.isNotEmpty(clientInfo.getClientId())) {
            appInfo.addParameter(ApplicationConstants.OAUTH_CLIENT_ID, clientInfo.getClientId());
        }
        if (StringUtils.isNotEmpty(clientInfo.getSecret())) {
            appInfo.addParameter(ApplicationConstants.OAUTH_CLIENT_SECRET, clientInfo.getSecret());
        }
        String additionalProperties = new Gson().toJson(clientInfo);
        appInfo.addParameter(APIConstants.JSON_ADDITIONAL_PROPERTIES,
                new Gson().fromJson(additionalProperties, Map.class));
        return appInfo;
    }

    private ClientInfoList toClientInfoList(ClientInfo clientInfo) {

        ClientInfoList clientInfoList = new ClientInfoList();
        clientInfoList.getClients().add(clientInfo);
        return clientInfoList;
    }

    private ClientInfo fromOauthAppRequestToClientInfo(OAuthAppRequest oAuthAppRequest) {

        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setClientAuthnType("SECRET");
        OAuthApplicationInfo oAuthApplicationInfo = oAuthAppRequest.getOAuthApplicationInfo();
        String userId = (String) oAuthApplicationInfo.getParameter(ApplicationConstants.
                OAUTH_CLIENT_USERNAME);
        String userNameForSp = MultitenantUtils.getTenantAwareUsername(userId);
        String domain = UserCoreUtil.extractDomainFromName(userNameForSp);
        if (domain != null && !domain.isEmpty() && !UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME.equals(domain)) {
            userNameForSp = userNameForSp.replace(UserCoreConstants.DOMAIN_SEPARATOR, "_");
        }
        String applicationName = oAuthApplicationInfo.getClientName();
        String keyType = (String) oAuthApplicationInfo.getParameter(ApplicationConstants.APP_KEY_TYPE);
        String callBackURL = oAuthApplicationInfo.getCallBackURL();
        if (keyType != null) {
            applicationName = userNameForSp.concat(applicationName).concat("_").concat(keyType);
        }
        List<String> grantTypes = new ArrayList<>();

        if (oAuthApplicationInfo.getParameter(APIConstants.JSON_GRANT_TYPES) != null) {
            grantTypes =
                    Arrays.asList(
                            ((String) oAuthApplicationInfo.getParameter(APIConstants.JSON_GRANT_TYPES)).split(","));
        }
        Object parameter = oAuthApplicationInfo.getParameter(APIConstants.JSON_ADDITIONAL_PROPERTIES);
        Map<String, Object> additionalProperties = new HashMap<>();
        if (parameter instanceof String) {
            additionalProperties = new Gson().fromJson((String) parameter, Map.class);
        }
        clientInfo.setName(applicationName);
        if (!grantTypes.isEmpty()) {
            clientInfo.setGrantTypes(grantTypes);
        }
        if (StringUtils.isNotEmpty(callBackURL)) {
            String[] calBackUris = callBackURL.split(",");
            clientInfo.setRedirectUris(Arrays.asList(calBackUris));
        }

        if (additionalProperties.containsKey(APIConstants.JSON_CLIENT_ID)) {
            clientInfo.setClientId((String) additionalProperties.get(APIConstants.JSON_CLIENT_ID));
        } else if (StringUtils.isNotEmpty(oAuthApplicationInfo.getClientId())) {
            clientInfo.setClientId(oAuthApplicationInfo.getClientId());
        } else {
            clientInfo.setClientId(UUID.randomUUID().toString());
        }
        if (additionalProperties.containsKey(APIConstants.JSON_CLIENT_SECRET)) {
            clientInfo.setClientId((String) additionalProperties.get(APIConstants.JSON_CLIENT_SECRET));
        } else if (StringUtils.isNotEmpty(oAuthApplicationInfo.getClientSecret())) {
            clientInfo.setSecret(oAuthApplicationInfo.getClientSecret());
        } else {
            clientInfo.setSecret(UUID.randomUUID().toString());
        }
        if (additionalProperties.containsKey(PingFederateConstants.BYPASS_APPROVAL_PAGES)) {
            clientInfo.setBypassApprovalPage(Boolean.parseBoolean(
                    (String) additionalProperties.get(PingFederateConstants.BYPASS_APPROVAL_PAGES)));
        }
        if (additionalProperties.containsKey(PingFederateConstants.RESTRICT_RESPONSE_TYPES)) {
            clientInfo.setBypassApprovalPage(Boolean.parseBoolean(
                    (String) additionalProperties.get(PingFederateConstants.BYPASS_APPROVAL_PAGES)));
        }
        clientInfo.setDescription(clientInfo.getName());
        return clientInfo;
    }

    @Override
    public OAuthApplicationInfo updateApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {

        if (oAuthAppRequest.getOAuthApplicationInfo() != null) {
            ClientInfo clientInfo = fromOauthAppRequestToClientInfo(oAuthAppRequest);
            pingFederateDCRClient.updateApplication(toClientInfoList(clientInfo));
        }
        return null;
    }

    @Override
    public void deleteApplication(String clientId) throws APIManagementException {

        Response response = pingFederateDCRClient.deleteApplication(clientId);
        if (response.status() == HttpStatus.SC_OK) {
            log.debug("Oauth Client Related to " + clientId + " Deleted successfully from PingFederate Server");
        } else {
            throw new APIManagementException("Error while Deleting Client Application from PingFederate Server");
        }
    }

    @Override
    public OAuthApplicationInfo retrieveApplication(String clientId) throws APIManagementException {

        ClientInfo application = pingFederateDCRClient.getApplication(clientId);
        if (application != null) {
            return fromClientInfoToOauthApplicationInfo(application);
        }
        return null;
    }

    @Override
    public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest accessTokenRequest)
            throws APIManagementException {

        AccessTokenInfo tokenInfo;

        if (accessTokenRequest == null) {
            log.warn("No information available to generate Token.");
            return null;
        }
        String scopes = null;
        if (accessTokenRequest.getScope() != null) {
            scopes = String.join(" ", accessTokenRequest.getScope());
        }

        TokenInfo tokenResponse;

        try {
            tokenResponse = authClient.generate(accessTokenRequest.getClientId(),
                    accessTokenRequest.getClientSecret(), APIConstants.GRANT_TYPE_VALUE, scopes);
        } catch (KeyManagerClientException e) {
            throw new APIManagementException("Error occurred while calling token endpoint!", e);
        }

        tokenInfo = new AccessTokenInfo();
        if (StringUtils.isNotEmpty(tokenResponse.getScope())) {
            tokenInfo.setScope(tokenResponse.getScope().split(" "));
        } else {
            tokenInfo.setScope(new String[0]);
        }
        tokenInfo.setAccessToken(tokenResponse.getToken());
        tokenInfo.setValidityPeriod(tokenResponse.getExpiry());

        return tokenInfo;
    }

    @Override
    public String getNewApplicationConsumerSecret(AccessTokenRequest accessTokenRequest) throws APIManagementException {

        ClientInfo application = pingFederateDCRClient.getApplication(accessTokenRequest.getClientId());
        application.setSecret(UUID.randomUUID().toString());
        application.setForceSecretChange(true);
        pingFederateDCRClient.updateApplication(toClientInfoList(application));
        return null;
    }

    @Override
    public AccessTokenInfo getTokenMetaData(String accessToken) throws APIManagementException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Getting access token metadata from authorization server. Access token %s",
                    accessToken));
        }
        AccessTokenInfo tokenInfo = new AccessTokenInfo();
        IntrospectInfo introspectInfo = introspectionClient.introspect(accessToken);
        tokenInfo.setTokenValid(introspectInfo.isActive());

        if (tokenInfo.isTokenValid()) {

            long expiryTime = introspectInfo.getExpiry();
            tokenInfo.addParameter(APIConstants.JwtTokenConstants.EXPIRY_TIME, expiryTime);

            if (StringUtils.isNotEmpty(introspectInfo.getScope())) {
                tokenInfo.setScope(introspectInfo.getScope().split("\\s+"));
            }
            tokenInfo.setConsumerKey(introspectInfo.getClientId());
            tokenInfo.setEndUserName(introspectInfo.getUsername());
            return tokenInfo;
        }
        return null;
    }

    @Override
    public KeyManagerConfiguration getKeyManagerConfiguration() throws APIManagementException {

        return configuration;
    }

    @Override
    public OAuthApplicationInfo mapOAuthApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        // PingFederate doesn't support to retrieve secret therefore we only check existence.
        OAuthApplicationInfo oAuthApplicationInfo = oAuthAppRequest.getOAuthApplicationInfo();
        if (oAuthApplicationInfo != null) {
            ClientInfo application =
                    pingFederateDCRClient.getApplication(oAuthAppRequest.getOAuthApplicationInfo().getClientId());
            if (application != null) {
                return fromClientInfoToOauthApplicationInfo(application);
            }
        }
        return null;
    }

    @Override
    public void loadConfiguration(KeyManagerConfiguration keyManagerConfiguration) throws APIManagementException {

        this.configuration = keyManagerConfiguration;
        String clientRegistrationEndpoint =
                (String) configuration.getParameter(APIConstants.KeyManager.CLIENT_REGISTRATION_ENDPOINT);
        String introspectionEndpoint =
                (String) configuration.getParameter(APIConstants.KeyManager.INTROSPECTION_ENDPOINT);
        String username = (String) configuration.getParameter(PingFederateConstants.USERNAME);
        String password = (String) configuration.getParameter(PingFederateConstants.PASSWORD);
        String clientId = (String) configuration.getParameter(PingFederateConstants.TOKEN_VALIDATION_CLIENT_ID);
        String clientSecret = (String) configuration.getParameter(PingFederateConstants.TOKEN_VALIDATION_CLIENT_SECRET);
        tokenEndpoint = (String) configuration.getParameter(APIConstants.KeyManager.TOKEN_ENDPOINT);
        if (StringUtils.isNotEmpty(clientRegistrationEndpoint) && StringUtils.isNotEmpty(username) &&
                StringUtils.isNotEmpty(password)) {
            pingFederateDCRClient =
                    Feign.builder().client(new ApacheFeignHttpClient(APIUtil.getHttpClient(clientRegistrationEndpoint)))
                            .encoder(new GsonEncoder()).decoder(new GsonDecoder())
                            .logger(new Slf4jLogger())
                            .requestInterceptor(new BasicAuthRequestInterceptor(username, password))
                            .target(PingFederateDCRClient.class, clientRegistrationEndpoint);
        }
        if (StringUtils.isNotEmpty(introspectionEndpoint) && StringUtils.isNotEmpty(clientId) &&
                StringUtils.isNotEmpty(clientSecret)) {
            introspectionClient =
                    Feign.builder().client(new ApacheFeignHttpClient(APIUtil.getHttpClient(introspectionEndpoint)))
                            .encoder(new FormEncoder()).decoder(new GsonDecoder())
                            .logger(new Slf4jLogger())
                            .requestInterceptor(new BasicAuthRequestInterceptor(clientId, clientSecret))
                            .target(IntrospectClient.class, introspectionEndpoint);
        }
        if (StringUtils.isNotEmpty(tokenEndpoint)) {
            authClient = Feign.builder().client(new ApacheFeignHttpClient(APIUtil.getHttpClient(tokenEndpoint)))
                    .encoder(new GsonEncoder()).decoder(new GsonDecoder()).logger(new Slf4jLogger())
                    .errorDecoder(new KMClientErrorDecoder()).encoder(new FormEncoder())
                    .target(AuthClient.class, tokenEndpoint);
        }
    }

    @Override
    public boolean registerNewResource(API api, Map map) throws APIManagementException {

        return false;
    }

    @Override
    public Map getResourceByApiId(String s) throws APIManagementException {

        return null;
    }

    @Override
    public boolean updateRegisteredResource(API api, Map map) throws APIManagementException {

        return false;
    }

    @Override
    public void deleteRegisteredResourceByAPIId(String s) throws APIManagementException {

    }

    @Override
    public void deleteMappedApplication(String s) throws APIManagementException {

    }

    @Override
    public Set<String> getActiveTokensByConsumerKey(String s) throws APIManagementException {

        return null;
    }

    @Override
    public AccessTokenInfo getAccessTokenByConsumerKey(String s) throws APIManagementException {

        return null;
    }

    @Override
    public Map<String, Set<Scope>> getScopesForAPIS(String s) throws APIManagementException {

        return null;
    }

    @Override
    public void registerScope(Scope scope) throws APIManagementException {

    }

    @Override
    public Scope getScopeByName(String s) throws APIManagementException {

        return null;
    }

    @Override
    public Map<String, Scope> getAllScopes() throws APIManagementException {

        return null;
    }

    @Override
    public void deleteScope(String s) throws APIManagementException {

    }

    @Override
    public void updateScope(Scope scope) throws APIManagementException {

    }

    @Override
    public boolean isScopeExists(String s) throws APIManagementException {

        return false;
    }

    public String getType() {

        return PingFederateConstants.PING_FEDERATE_TYPE;
    }
}
