package org.wso2.carbon.identity.sso.saml.extension.eidas;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOReqValidationResponseDTO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.identity.sso.saml.validators.SPInitSSOAuthnRequestValidator;

import java.io.IOException;

/**
 * This class is used to override existing implementation on validation of SP initiated authentication request
 * for eIDAS message format
 */
public class EidasSPInitSSOAuthnRequestValidator extends SPInitSSOAuthnRequestValidator {

    private static Log log = LogFactory.getLog(EidasSPInitSSOAuthnRequestValidator.class);

    public EidasSPInitSSOAuthnRequestValidator(AuthnRequest authnReq) throws IdentityException {

        super(authnReq);
    }

    /**
     * @return
     * @throws IdentityException
     */
    @Override
    public SAMLSSOReqValidationResponseDTO validate() throws IdentityException {

        SAMLSSOReqValidationResponseDTO validationResponseDTO = super.validate();
        validateAuthnContextComparison(validationResponseDTO);
        validateForceAuthn(validationResponseDTO);
        validateIsPassive(validationResponseDTO);
        return validationResponseDTO;
    }

    private void validateIsPassive(SAMLSSOReqValidationResponseDTO validationResponseDTO) throws IdentityException {

        String errorResp;
        if (validationResponseDTO.isPassive()) {
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
            setErrorResponse(validationResponseDTO, errorResp);
        }
    }

    private void validateForceAuthn(SAMLSSOReqValidationResponseDTO validationResponseDTO) throws IdentityException {

        String errorResp;
        if (!validationResponseDTO.isForceAuthn()) {
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
            setErrorResponse(validationResponseDTO, errorResp);
        }
    }

    private void validateAuthnContextComparison(SAMLSSOReqValidationResponseDTO validationResponseDTO) throws IdentityException {

        String errorResp;
        if (validationResponseDTO.getRequestedAuthnContextComparison() !=
                AuthnContextComparisonTypeEnumeration.MINIMUM.toString()) {
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
            setErrorResponse(validationResponseDTO, errorResp);
        }
    }

    private void setErrorResponse(SAMLSSOReqValidationResponseDTO validationResponseDTO, String errorResp) {

        validationResponseDTO.setValid(false);
        validationResponseDTO.setResponse(errorResp);
        validationResponseDTO.setValid(false);
    }
}
