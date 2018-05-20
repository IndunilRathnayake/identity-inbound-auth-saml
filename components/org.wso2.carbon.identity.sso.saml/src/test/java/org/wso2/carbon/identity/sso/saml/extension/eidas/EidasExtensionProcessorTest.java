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

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.RequestAbstractType;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.w3c.dom.NodeList;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.TestUtils;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOReqValidationResponseDTO;
import org.wso2.carbon.identity.sso.saml.extension.eidas.model.RequestedAttributes;

import static org.mockito.MockitoAnnotations.initMocks;

public class EidasExtensionProcessorTest {

    @InjectMocks
    EidasExtensionProcessor eidasExtensionProcessor;

    @Mock
    RequestAbstractType request;

    @Mock
    SAMLSSOReqValidationResponseDTO validationResp;

    @BeforeMethod
    public void init() throws Exception {

        initMocks(this);
        eidasExtensionProcessor = new EidasExtensionProcessor();
        String requestFile = "src/test/resources/sample_eidas_request.xml";
        request = (AuthnRequest) TestUtils.unmarshallElement(requestFile);
        validationResp = new SAMLSSOReqValidationResponseDTO();
    }

    @Test(priority = 0)
    public void testCanHandle() throws IdentityException {

        Assert.assertTrue(eidasExtensionProcessor.canHandle(request), "Error in validating whether can handle " +
                "the eidas request");
    }

    @Test(priority = 1)
    public void testProcessSAMLExtensions() throws IdentityException {

        String eidas_requestType = "eidas";
        eidasExtensionProcessor.processSAMLExtensions(request, validationResp);
        Assert.assertEquals(validationResp.getRequestType(), eidas_requestType, "Error in setting the " +
                "request type.");
        Assert.assertNotEquals(validationResp.getRequestedAttributes().size(),  0, "Error in processing " +
                "and setting the requested attributes retrieved in request.");
        NodeList requestedAttrs = request.getExtensions().getUnknownXMLObjects(RequestedAttributes.DEFAULT_ELEMENT_NAME)
                .get(0).getDOM().getChildNodes();
        Assert.assertEquals(requestedAttrs.getLength(),  validationResp.getRequestedAttributes().size(), "Error in " +
                "processing and setting the requested attributes retrieved in request.");
    }

    @Test(priority = 2)
    public void testValidateSAMLExtensions() throws IdentityException {

        validationResp.setValid(true);
        validationResp.setForceAuthn(true);
        validationResp.setPassive(false);
        validationResp.setRequestedAuthnContextComparison(AuthnContextComparisonTypeEnumeration.MINIMUM.toString());
        eidasExtensionProcessor.validateSAMLExtensions(request, validationResp);
        Assert.assertTrue(validationResp.isValid(), "Error when validating the SAML extensions in request");
    }
}
