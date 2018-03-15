/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
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
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.core.*;
import org.opensaml.xml.XMLObject;
import org.w3c.dom.NodeList;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOReqValidationResponseDTO;
import org.wso2.carbon.identity.sso.saml.extension.ExtensionProcessor;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class EidasExtensionProcessor implements ExtensionProcessor {
    private static Log log = LogFactory.getLog(EidasExtensionProcessor.class);

    public void processExtensions(AuthnRequest request, SAMLSSOReqValidationResponseDTO validationResp) throws IdentityException {
        log.debug("Process the extensions for EIDAS messageFormat");

        Extensions extensions = request.getExtensions();
        XMLObject spType = extensions.getUnknownXMLObjects(SPType.DEFAULT_ELEMENT_NAME).get(0);

        if (!spType.getDOM().getNodeValue().equals(EidasConstants.EIDAS_SP_TYPE_PUBLIC) ||
                !spType.getDOM().getNodeValue().equals(EidasConstants.EIDAS_SP_TYPE_PRIVATE)) {
            validationResp.setValid(false);
            String errorResp = null;
            try {
                errorResp = SAMLSSOUtil.buildErrorResponse(
                        SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, "SP Type should be either public or private.",
                        validationResp.getDestination());
            } catch (IOException e) {
                throw IdentityException.error("Issue in building error response.", e);
            }
            if (log.isDebugEnabled()) {
                log.debug("Invalid Request message. SP Type found " + spType.getDOM().getNodeValue());
            }
            validationResp.setResponse(errorResp);
            validationResp.setValid(false);
        }


        XMLObject requestedAttrs = extensions.getUnknownXMLObjects(RequestedAttributes.DEFAULT_ELEMENT_NAME).get(0);
        NodeList nodeList = requestedAttrs.getDOM().getChildNodes();
        List<ClaimMapping> claimMappings = new ArrayList<>();

        validationResp.setRequestedAttributes(new ArrayList<>());
        for (int i = 0; i < nodeList.getLength(); i++) {
            ClaimMapping claimMapping = new ClaimMapping();
            Claim remoteClaim = new Claim();
            String nameFormat = nodeList.item(i).getAttributes().getNamedItem(EidasConstants.EIDAS_ATTRIBUTE_NAME_FORMAT)
                    .getNodeValue();
            if (!nameFormat.equals(EidasConstants.EIDAS_ATTRIBUTE_NAME_FORMAT_URI)) {
                validationResp.setValid(false);
                String errorResp = null;
                try {
                    errorResp = SAMLSSOUtil.buildErrorResponse(
                            SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, "NameFormat should be " +
                                    EidasConstants.EIDAS_ATTRIBUTE_NAME_FORMAT_URI,
                            validationResp.getDestination());
                } catch (IOException e) {
                    throw IdentityException.error("Issue in building error response.", e);
                }
                if (log.isDebugEnabled()) {
                    log.debug("Invalid Request message. NameFormat found " + nameFormat);
                }
                validationResp.setResponse(errorResp);
                validationResp.setValid(false);
            }
            remoteClaim.setClaimUri(nodeList.item(i).getAttributes().getNamedItem(EidasConstants.EIDAS_ATTRIBUTE_NAME)
                    .getNodeValue());
            claimMapping.setRemoteClaim(remoteClaim);
            claimMapping.setRequested(Boolean.parseBoolean(nodeList.item(i).getAttributes().getNamedItem(
                    EidasConstants.EIDAS_ATTRIBUTE_REQUIRED).getNodeValue()));
            validationResp.getRequestedAttributes().add(claimMapping);
        }
    }

    public void processExtensions(Response response, AuthnRequest request, Assertion assertion) throws IdentityException {
        log.debug("Process the extensions for EIDAS messageFormat");

        Extensions extensions = request.getExtensions();
        XMLObject requestedAttrs = extensions.getUnknownXMLObjects(RequestedAttributes.DEFAULT_ELEMENT_NAME).get(0);
        NodeList nodeList = requestedAttrs.getDOM().getChildNodes();

        List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
        List<String> mandatoryClaims = new ArrayList<>();

        for (int i = 0; i < nodeList.getLength(); i++) {
            String spClaimUri = nodeList.item(i).getAttributes().getNamedItem(EidasConstants.EIDAS_ATTRIBUTE_NAME)
                    .getNodeValue();
            boolean isRequired = Boolean.parseBoolean(nodeList.item(i).getAttributes()
                    .getNamedItem(EidasConstants.EIDAS_ATTRIBUTE_REQUIRED).getNodeValue());
            if (isRequired) {
                mandatoryClaims.add(spClaimUri);
            }
        }

        boolean isMandatoryClaimPresent = false;
        for (String mandatoryClaim : mandatoryClaims) {
            for (AttributeStatement attributeStatement : attributeStatements) {
                for (Attribute attribute : attributeStatement.getAttributes()) {
                    if (attribute.getName().equals(mandatoryClaim)) {
                        isMandatoryClaimPresent = true;
                        break;
                    }
                }
                if (isMandatoryClaimPresent) {
                    break;
                }
            }
            if (!isMandatoryClaimPresent) {
                break;
            }
        }

        if (!isMandatoryClaimPresent) {
            response.setStatus(SAMLSSOUtil.buildStatus(SAMLSSOConstants.StatusCodes.SUCCESS_CODE, null));
        }

        for (AttributeStatement attributeStatement : attributeStatements) {
            for (Attribute attribute : attributeStatement.getAttributes()) {
                attribute.setNameFormat(EidasConstants.EIDAS_ATTRIBUTE_NAME_FORMAT_URI);
            }
        }
    }
}
