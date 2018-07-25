/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.client.authentication;

import org.apache.axiom.util.base64.Base64Utils;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.io.Charsets;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthConsumerDAO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;

/**
 * This class is dedicated for authenticating 'Public Clients'. Public clients do not need a client secret to be
 * validated. This type of authentication is regularly utilised by native OAuth clients.
 */
public class PublicOAuthClientAuthenticator extends AbstractOAuthClientAuthenticator {


    private static Log log = LogFactory.getLog(PublicOAuthClientAuthenticator.class);
    private static String CREDENTIAL_SEPARATOR = ":";
    private static String SIMPLE_CASE_AUTHORIZATION_HEADER = "authorization";
    private static String BASIC_PREFIX = "Basic";
    private static int CREDENTIAL_LENGTH = 1;

    /**
     * Returns the execution order of this authenticator
     *
     * @return Execution place within the order
     */
    @Override
    public int getPriority() {

        return 100;
    }

    /**
     * @param request                 HttpServletRequest which is the incoming request.
     * @param bodyParams              Body parameter map of the request.
     * @param oAuthClientAuthnContext OAuth client authentication context.
     * @return Whether the authentication is successful or not.
     * @throws OAuthClientAuthnException
     */
    @Override
    public boolean authenticateClient(HttpServletRequest request, Map<String, List> bodyParams, OAuthClientAuthnContext
            oAuthClientAuthnContext) throws OAuthClientAuthnException {

        return true;
    }


    /**
     * Returns whether the incoming request can be authenticated or not using the given inputs.
     *
     * @param request    HttpServletRequest which is the incoming request.
     * @param bodyParams Body parameters present in the request.
     * @param context    OAuth2 client authentication context.
     * @return
     */
    @Override
    public boolean canAuthenticate(HttpServletRequest request, Map<String, List> bodyParams, OAuthClientAuthnContext
            context) {

        OAuthConsumerDAO oAuthConsumerDAO = new OAuthConsumerDAO();

        try {
            if (isClientIdExistsAsParams(bodyParams) && oAuthConsumerDAO.getPublicClientStatusOfApp(context.
                    getClientId())) {
                return true;
            }
        } catch (IdentityOAuthAdminException e) {
            if (log.isDebugEnabled()) {
                log.debug("Public client status could not be retrieved.");
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Client ID not present as Authorization header nor as body params. Hence " +
                    "returning false");
        }
        return false;
    }

    /**
     * Get the name of the OAuth2 client authenticator.
     *
     * @return The name of the OAuth2 client authenticator.
     */
    @Override
    public String getName() {

        return "PublicOAuthClientAuthenticator";
    }

    /**
     * Retrives the client ID which is extracted from incoming request.
     *
     * @param request                 HttpServletRequest.
     * @param bodyParams              Body paarameter map of the incoming request.
     * @param oAuthClientAuthnContext OAuthClientAuthentication context.
     * @return Client ID of the OAuth2 client.
     * @throws OAuthClientAuthnException OAuth client authentication context.
     */
    @Override
    public String getClientId(HttpServletRequest request, Map<String, List> bodyParams, OAuthClientAuthnContext
            oAuthClientAuthnContext) throws OAuthClientAuthnException {

        setClientCredentialsFromParam(bodyParams, oAuthClientAuthnContext);
        return oAuthClientAuthnContext.getClientId();
    }


    protected boolean isClientIdExistsAsParams(Map<String, List> contentParam) {

        Map<String, String> stringContent = getBodyParameters(contentParam);
        return (StringUtils.isNotEmpty(stringContent.get(OAuth.OAUTH_CLIENT_ID)));
    }

    /**
     * Sets client id to the OAuth client authentication context.
     *
     * @param bodyParams Body parameters of the incoming request.
     * @param context      OAuth client authentication context.
     */
    protected void setClientCredentialsFromParam(Map<String, List> bodyParams, OAuthClientAuthnContext context) {

        Map<String, String> stringContent = getBodyParameters(bodyParams);
        context.setClientId(stringContent.get(OAuth.OAUTH_CLIENT_ID));

    }

}
