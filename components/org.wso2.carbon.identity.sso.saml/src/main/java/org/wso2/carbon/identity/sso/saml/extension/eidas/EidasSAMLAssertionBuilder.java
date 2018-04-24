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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.builders.assertion.DefaultSAMLAssertionBuilder;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.io.Serializable;

/**
 * This class is used to override existing implementation on Assertion building to support
 * eIDAS message format
 */
public class EidasSAMLAssertionBuilder extends DefaultSAMLAssertionBuilder
        implements Serializable {

    private final static Log log = LogFactory.getLog(EidasSAMLAssertionBuilder.class);

    /**
     * This method is used to initialize
     *
     * @throws IdentityException If error occurred
     */
    @Override
    public void init() throws IdentityException {

    }

    /**
     * This method is used to build assertion according to the eIDAS specification
     *
     * @param authReqDTO Authntication request data object
     * @param notOnOrAfter       Assertion expiration time gap
     * @param sessionId          Created session id
     * @return Assertion Set of element which contain authentication information
     * @throws IdentityException If unable to collect issuer information
     */
    @Override
    public Assertion buildAssertion(Response response, SAMLSSOAuthnReqDTO authReqDTO, DateTime notOnOrAfter, String sessionId)
            throws IdentityException {

        try {
            DateTime currentTime = new DateTime();
            Assertion samlAssertion = new AssertionBuilder().buildObject();

            this.setBasicInfo(samlAssertion, currentTime);

            this.setSubject(authReqDTO, notOnOrAfter, samlAssertion);

            this.addAuthStatement(authReqDTO, sessionId, samlAssertion);

            this.addAttributeStatements(authReqDTO, samlAssertion);

            String samlReq = authReqDTO.getRequestMessageString();

            AuthnRequest authRequest = (AuthnRequest) SAMLSSOUtil.unmarshall(SAMLSSOUtil.decodeForPost(samlReq));

            this.setConditions(authReqDTO, currentTime, notOnOrAfter, samlAssertion);

            if (authRequest.getExtensions() != null) {
                EidasExtensionProcessor eidasExtensionProcessor = new EidasExtensionProcessor();
                eidasExtensionProcessor.processExtensions(response, authRequest, samlAssertion);
            }

            this.setSignature(authReqDTO, samlAssertion);

            return samlAssertion;

        } catch (Exception e) {
            throw IdentityException.error("Error when building SAML assertion", e);
        }
    }
}
