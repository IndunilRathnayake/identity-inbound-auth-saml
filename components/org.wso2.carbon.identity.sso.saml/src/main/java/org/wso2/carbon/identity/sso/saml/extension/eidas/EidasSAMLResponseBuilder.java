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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.sso.saml.extension.eidas;

import org.opensaml.saml2.core.Response;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.builders.DefaultResponseBuilder;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;

/**
 * This class is used to override existing implementation on Response Building to support
 * eIDAS message format
 */
public class EidasSAMLResponseBuilder extends DefaultResponseBuilder {

    /**
     * This method is used to build response according to the eIDAS specification
     *
     * @param authReqDTO
     * @param sessionId
     * @return
     * @throws IdentityException
     */
    @Override
    public Response buildResponse(SAMLSSOAuthnReqDTO authReqDTO, String sessionId)
            throws IdentityException {

        Response response = super.buildResponse(authReqDTO, sessionId);
        EidasExtensionProcessor eidasExtensionProcessor = new EidasExtensionProcessor();
        eidasExtensionProcessor.processExtensions(response, authReqDTO);
        return response;
    }
}
