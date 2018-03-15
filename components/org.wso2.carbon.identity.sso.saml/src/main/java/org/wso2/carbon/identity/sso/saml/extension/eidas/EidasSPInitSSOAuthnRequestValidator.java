package org.wso2.carbon.identity.sso.saml.extension.eidas;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOReqValidationResponseDTO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.identity.sso.saml.validators.SPInitSSOAuthnRequestValidator;
import org.opensaml.saml2.core.AuthnRequest;
import org.wso2.carbon.identity.base.IdentityException;

import java.io.IOException;

public class EidasSPInitSSOAuthnRequestValidator extends SPInitSSOAuthnRequestValidator {

    private static Log log = LogFactory.getLog(EidasSPInitSSOAuthnRequestValidator.class);

    public EidasSPInitSSOAuthnRequestValidator(AuthnRequest authnReq) throws IdentityException {
        super(authnReq);
    }

    public SAMLSSOReqValidationResponseDTO validate() throws IdentityException {
        SAMLSSOReqValidationResponseDTO validationResponseDTO = super.validate();
        if(validationResponseDTO.getRequestedAuthnContextComparison() !=
                AuthnContextComparisonTypeEnumeration.MINIMUM.toString()) {
            validationResponseDTO.setValid(false);
            String errorResp = null;
            try {
                errorResp = SAMLSSOUtil.buildErrorResponse(
                        SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                        "Comparison of RequestedAuthnContext should be minimum.",
                        validationResponseDTO.getDestination());
            } catch (IOException e) {
                throw IdentityException.error("Issue in building error response.", e);
            }
            if (log.isDebugEnabled()) {
                log.debug("Invalid Request message. Comparison of RequestedAuthnContext is " +
                        validationResponseDTO.getRequestedAuthnContextComparison());
            }
            validationResponseDTO.setResponse(errorResp);
            validationResponseDTO.setValid(false);
            return validationResponseDTO;
        }

        if(!validationResponseDTO.isForceAuthn()) {
            validationResponseDTO.setValid(false);
            String errorResp = null;
            try {
                errorResp = SAMLSSOUtil.buildErrorResponse(
                        SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                        "ForceAuthn MUST be set to true",
                        validationResponseDTO.getDestination());
            } catch (IOException e) {
                throw IdentityException.error("Issue in building error response.", e);
            }
            if (log.isDebugEnabled()) {
                log.debug("Invalid Request message. ForceAuthn is " + validationResponseDTO.isForceAuthn());
            }
            validationResponseDTO.setResponse(errorResp);
            validationResponseDTO.setValid(false);
            return validationResponseDTO;
        }

        if(validationResponseDTO.isPassive()) {
            validationResponseDTO.setValid(false);
            String errorResp = null;
            try {
                errorResp = SAMLSSOUtil.buildErrorResponse(
                        SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                        "isPassive SHOULD be set to false.",
                        validationResponseDTO.getDestination());
            } catch (IOException e) {
                throw IdentityException.error("Issue in building error response.", e);
            }
            if (log.isDebugEnabled()) {
                log.debug("Invalid Request message. isPassive found " + validationResponseDTO.isPassive());
            }
            validationResponseDTO.setResponse(errorResp);
            validationResponseDTO.setValid(false);
            return validationResponseDTO;
        }

        if(validationResponseDTO.getNameIDPolicy() == null) {
            validationResponseDTO.setValid(false);
            String errorResp = null;
            try {
                errorResp = SAMLSSOUtil.buildErrorResponse(
                        SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                        "NameIDPolicy SHOULD be included.",
                        validationResponseDTO.getDestination());
            } catch (IOException e) {
                throw IdentityException.error("Issue in building error response.", e);
            }
            if (log.isDebugEnabled()) {
                log.debug("Invalid Request message. NameIDPolicy is not included");
            }
            validationResponseDTO.setResponse(errorResp);
            validationResponseDTO.setValid(false);
            return validationResponseDTO;
        }

        return validationResponseDTO;
    }
}
