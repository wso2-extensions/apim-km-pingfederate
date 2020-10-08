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

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.impl.dto.JWTValidationInfo;
import org.wso2.carbon.apimgt.impl.jwt.JWTValidatorImpl;
import org.wso2.carbon.apimgt.impl.jwt.SignedJWTInfo;

import java.util.Map;

/**
 * Extended implementation to handle subject claim.
 */
public class PingFederateJWTValidatorImpl extends JWTValidatorImpl {

    @Override
    public JWTValidationInfo validateToken(SignedJWTInfo signedJWTInfo) throws APIManagementException {

        JWTValidationInfo jwtValidationInfo = super.validateToken(signedJWTInfo);
        if (jwtValidationInfo != null) {
            if (jwtValidationInfo.isValid()) {
                if (StringUtils.isEmpty(jwtValidationInfo.getUser())) {
                    Map<String, Object> claims = jwtValidationInfo.getClaims();
                    if (claims != null) {
                        if (claims.containsKey(PingFederateConstants.DEFAULT_SUBJECT_CLAIM)) {
                            jwtValidationInfo.setUser((String) claims.get(PingFederateConstants.DEFAULT_SUBJECT_CLAIM));
                        } else if (claims.containsKey(PingFederateConstants.CLIENT_ID_CLAIM)) {
                            jwtValidationInfo.setUser((String) claims.get(PingFederateConstants.CLIENT_ID_CLAIM));
                        }
                    }
                }
            }
        }
        return jwtValidationInfo;
    }
}
