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

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.impl.XSAnyImpl;
import org.w3c.dom.NodeList;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOReqValidationResponseDTO;
import org.wso2.carbon.identity.sso.saml.extension.ExtensionProcessor;
import org.wso2.carbon.identity.sso.saml.extension.eidas.model.RequestedAttributes;
import org.wso2.carbon.identity.sso.saml.extension.eidas.model.SPType;
import org.wso2.carbon.identity.sso.saml.extension.eidas.util.EidasConstants;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * This class is used to process the Eidas SAML extensions in authentication request
 */
public class EidasExtensionProcessor implements ExtensionProcessor {
    private static Log log = LogFactory.getLog(EidasExtensionProcessor.class);
    private static String errorMsg = "202010 - Mandatory Attribute not found.";

    /**
     * Process the SAML extensions in authentication request for EIDAS message format
     *
     * @param request        Authentication request
     * @param validationResp reqValidationResponseDTO
     * @throws IdentityException
     */
    public void processExtensions(AuthnRequest request, SAMLSSOReqValidationResponseDTO validationResp)
            throws IdentityException {

        if (log.isDebugEnabled()) {
            log.debug("Process the extensions for EIDAS message format");
        }
        Extensions extensions = request.getExtensions();
        if (extensions != null) {
            processSPType(validationResp, extensions);
            processRequestedAttributes(validationResp, extensions);
        }
    }

    /**
     * Process the SAML extensions in authentication request for validating the response
     *
     * @param response
     * @param authReqDTO
     */
    public void processExtensions(Response response, SAMLSSOAuthnReqDTO authReqDTO) {

        if (log.isDebugEnabled()) {
            log.debug("Process the extensions for EIDAS message format");
        }
        setAuthnContextClassRef(response, authReqDTO);
        validateMandatoryRequestedAttr(response, authReqDTO);
    }

    private void validateMandatoryRequestedAttr(Response response, SAMLSSOAuthnReqDTO authReqDTO) {

        List<String> mandatoryClaims = new ArrayList<>();
        setAttributeNameFormat(response.getAssertions().get(0).getAttributeStatements());
        getMandatoryAttributes(authReqDTO, mandatoryClaims);

        boolean isMandatoryClaimPresent = validateMandatoryClaims(response, mandatoryClaims);

        if (!isMandatoryClaimPresent) {
            response.setStatus(SAMLSSOUtil.buildResponseStatus(SAMLSSOConstants.StatusCodes.IDENTITY_PROVIDER_ERROR,
                    errorMsg));
            response.getAssertions().get(0).getAttributeStatements().clear();

            NameID nameId = new NameIDBuilder().buildObject();
            nameId.setValue("NotAvailable");
            nameId.setFormat(NameIdentifier.UNSPECIFIED);
            response.getAssertions().get(0).getSubject().setNameID(nameId);
        }
    }

    private void setAuthnContextClassRef(Response response, SAMLSSOAuthnReqDTO authReqDTO) {

        response.getAssertions().get(0).getAuthnStatements().get(0).getAuthnContext().getAuthnContextClassRef()
                .setAuthnContextClassRef(authReqDTO.getAuthenticationContextClassRefList().get(0)
                        .getAuthenticationContextClassReference());
    }

    private void processRequestedAttributes(SAMLSSOReqValidationResponseDTO validationResp, Extensions extensions)
            throws IdentityException {

        if (CollectionUtils.isNotEmpty(extensions.getUnknownXMLObjects(RequestedAttributes.DEFAULT_ELEMENT_NAME))) {
            XMLObject requestedAttrs = extensions.getUnknownXMLObjects(RequestedAttributes.DEFAULT_ELEMENT_NAME).get(0);
            NodeList nodeList = requestedAttrs.getDOM().getChildNodes();
            validationResp.setRequestedAttributes(new ArrayList<>());

            for (int i = 0; i < nodeList.getLength(); i++) {
                ClaimMapping claimMapping = new ClaimMapping();
                Claim remoteClaim = new Claim();
                String nameFormat = nodeList.item(i).getAttributes().getNamedItem(EidasConstants.EIDAS_ATTRIBUTE_NAME_FORMAT)
                        .getNodeValue();
                validateAttributeNameFormat(validationResp, nameFormat);
                remoteClaim.setClaimUri(nodeList.item(i).getAttributes().getNamedItem(EidasConstants.EIDAS_ATTRIBUTE_NAME)
                        .getNodeValue());
                claimMapping.setRemoteClaim(remoteClaim);
                claimMapping.setRequested(Boolean.parseBoolean(nodeList.item(i).getAttributes().getNamedItem(
                        EidasConstants.EIDAS_ATTRIBUTE_REQUIRED).getNodeValue()));
                validationResp.getRequestedAttributes().add(claimMapping);
            }
        }
    }

    private void validateAttributeNameFormat(SAMLSSOReqValidationResponseDTO validationResp, String nameFormat)
            throws IdentityException {

        if (!nameFormat.equals(EidasConstants.EIDAS_ATTRIBUTE_NAME_FORMAT_URI)) {
            validationResp.setValid(false);
            String errorResp;
            try {
                errorResp = SAMLSSOUtil.buildErrorResponse(
                        SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, "NameFormat should be " +
                                EidasConstants.EIDAS_ATTRIBUTE_NAME_FORMAT_URI,
                        validationResp.getDestination());
            } catch (IOException e) {
                throw new IdentityException("Issue in building error response.", e);
            }
            if (log.isDebugEnabled()) {
                log.debug("Invalid Request message. NameFormat found " + nameFormat);
            }
            validationResp.setResponse(errorResp);
            validationResp.setValid(false);
        }
    }

    private void processSPType(SAMLSSOReqValidationResponseDTO validationResp, Extensions extensions)
            throws IdentityException {

        if (CollectionUtils.isNotEmpty(extensions.getUnknownXMLObjects(SPType.DEFAULT_ELEMENT_NAME))) {
            XMLObject spType = extensions.getUnknownXMLObjects(SPType.DEFAULT_ELEMENT_NAME).get(0);
            if (log.isDebugEnabled()) {
                log.debug("Process the SP Type: " + spType + " in the EIDAS message");
            }

            if (spType != null && isValidSPType((XSAnyImpl) spType)) {
                validationResp.setValid(false);
                String errorResp;
                try {
                    errorResp = SAMLSSOUtil.buildErrorResponse(
                            SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, "SP Type should be either public or private.",
                            validationResp.getDestination());
                } catch (IOException e) {
                    throw new IdentityException("Issue in building error response.", e);
                }
                if (log.isDebugEnabled()) {
                    log.debug("Invalid Request message. SP Type found " + spType.getDOM().getNodeValue());
                }
                validationResp.setResponse(errorResp);
                validationResp.setValid(false);
            }
        }
    }

    private boolean isValidSPType(XSAnyImpl spType) {

        return !spType.getTextContent().equals(EidasConstants.EIDAS_SP_TYPE_PUBLIC) &&
                !spType.getTextContent().equals(EidasConstants.EIDAS_SP_TYPE_PRIVATE);
    }

    private boolean validateMandatoryClaims(Response response, List<String> mandatoryClaims) {

        boolean isMandatoryClaimPresent = false;
        for (String mandatoryClaim : mandatoryClaims) {
            for (AttributeStatement attributeStatement : response.getAssertions().get(0).getAttributeStatements()) {
                if (attributeStatement.getAttributes().stream().anyMatch(attribute -> attribute.getName().equals(
                        mandatoryClaim))) {
                    isMandatoryClaimPresent = true;
                }
                if (isMandatoryClaimPresent) {
                    break;
                }
            }
            if (!isMandatoryClaimPresent) {
                break;
            }
        }
        return isMandatoryClaimPresent;
    }

    private void getMandatoryAttributes(SAMLSSOAuthnReqDTO authReqDTO, List<String> mandatoryClaims) {

        for (ClaimMapping requestedClaim : authReqDTO.getRequestedAttributes()) {
            if (requestedClaim.isMandatory()) {
                mandatoryClaims.add(requestedClaim.getRemoteClaim().getClaimUri());
            }
        }
    }

    private void setAttributeNameFormat(List<AttributeStatement> attributeStatements) {

        attributeStatements.forEach(attributeStatement -> attributeStatement.getAttributes().forEach(attribute ->
                attribute.setNameFormat(EidasConstants.EIDAS_ATTRIBUTE_NAME_FORMAT_URI)));
    }
}
