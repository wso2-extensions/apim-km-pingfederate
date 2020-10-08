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
package org.wso2.pingfederate.model;

import com.google.gson.annotations.SerializedName;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * DCR Client Info.
 */
public class ClientInfo {

    @SerializedName("name")
    private String name;
    @SerializedName("clientId")
    private String clientId;
    @SerializedName("redirectUris")
    private Object redirectUris = new ArrayList();
    @SerializedName("grantTypes")
    private Object grantTypes = new ArrayList<>();
    @SerializedName("description")
    private String description;
    @SerializedName("clientAuthnType")
    private String clientAuthnType;
    @SerializedName("secret")
    private String secret;
    @SerializedName("restrictedResponseTypes")
    private Object restrictedResponseTypes = new ArrayList<>();
    @SerializedName("restrictScopes")
    private boolean restrictScopes;
    @SerializedName("restrictedScopes")
    private Object restrictedScopes;
    @SerializedName("exclusiveScopes")
    private Object exclusiveScopes;
    @SerializedName("bypassApprovalPage")
    private boolean bypassApprovalPage;
    @SerializedName("forceSecretChange")
    private boolean forceSecretChange;

    public boolean isForceSecretChange() {

        return forceSecretChange;
    }

    public void setForceSecretChange(boolean forceSecretChange) {

        this.forceSecretChange = forceSecretChange;
    }

    public String getName() {

        return name;
    }

    public void setName(String name) {

        this.name = name;
    }

    public String getClientId() {

        return clientId;
    }

    public void setClientId(String clientId) {

        this.clientId = clientId;
    }

    public List<String> getRedirectUris() {

        if (redirectUris instanceof String) {
            return new ArrayList<>(Arrays.asList((String) redirectUris));
        }
        return (List<String>) redirectUris;
    }

    public void setRedirectUris(List<String> redirectUris) {

        this.redirectUris = redirectUris;
    }

    public List<String> getGrantTypes() {

        if (grantTypes instanceof String) {
            return new ArrayList<>(Arrays.asList((String) grantTypes));
        }
        return (List<String>) grantTypes;
    }

    public void setGrantTypes(List<String> grantTypes) {

        this.grantTypes = grantTypes;
    }

    public String getDescription() {

        return description;
    }

    public void setDescription(String description) {

        this.description = description;
    }

    public String getClientAuthnType() {

        return clientAuthnType;
    }

    public void setClientAuthnType(String clientAuthnType) {

        this.clientAuthnType = clientAuthnType;
    }

    public String getSecret() {

        return secret;
    }

    public void setSecret(String secret) {

        this.secret = secret;
    }

    public Object getRestrictedScopes() {

        return restrictedScopes;
    }

    public void setRestrictedScopes(Object restrictedScopes) {

        this.restrictedScopes = restrictedScopes;
    }

    public Object getExclusiveScopes() {

        return exclusiveScopes;
    }

    public void setExclusiveScopes(Object exclusiveScopes) {

        this.exclusiveScopes = exclusiveScopes;
    }

    public List<String> getRestrictedResponseTypes() {

        if (restrictedResponseTypes instanceof String) {
            return new ArrayList<>(Arrays.asList((String) restrictedResponseTypes));
        }
        return (List<String>) restrictedResponseTypes;
    }

    public void setRestrictedResponseTypes(List<String> restrictedResponseTypes) {

        this.restrictedResponseTypes = restrictedResponseTypes;
    }

    public boolean isRestrictScopes() {

        return restrictScopes;
    }

    public void setRestrictScopes(boolean restrictScopes) {

        this.restrictScopes = restrictScopes;
    }

    public boolean isBypassApprovalPage() {

        return bypassApprovalPage;
    }

    public void setBypassApprovalPage(boolean bypassApprovalPage) {

        this.bypassApprovalPage = bypassApprovalPage;
    }
}
