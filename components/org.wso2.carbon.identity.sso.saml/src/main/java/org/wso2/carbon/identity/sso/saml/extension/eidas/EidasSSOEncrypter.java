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
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.builders.X509CredentialImpl;
import org.wso2.carbon.identity.sso.saml.builders.assertion.DefaultSAMLAssertionBuilder;
import org.wso2.carbon.identity.sso.saml.builders.encryption.DefaultSSOEncrypter;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import javax.xml.namespace.QName;
import java.io.Serializable;
import java.security.cert.CertificateEncodingException;

/**
 * This class is used to override existing implementation on Assertion building to support
 * eIDAS message format
 */
public class EidasSSOEncrypter extends DefaultSSOEncrypter implements Serializable {

    private final static Log log = LogFactory.getLog(EidasSSOEncrypter.class);

    /**
     * This method is used to initialize
     *
     * @throws IdentityException If error occurred
     */
    @Override
    public void init() throws IdentityException {

    }

    @Override
    public EncryptedAssertion doEncryptedAssertion(Assertion assertion, X509Credential cred,
                                                   String alias, String assertionEncryptionAlgorithm,
                                                   String keyEncryptionAlgorithm) throws IdentityException {
        EncryptedAssertion encrypted = super.doEncryptedAssertion(assertion, cred, alias, assertionEncryptionAlgorithm, keyEncryptionAlgorithm);
        KeyInfo keyInfo = (KeyInfo) buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
        X509Data data = (X509Data) buildXMLObject(X509Data.DEFAULT_ELEMENT_NAME);
        X509Certificate cert = (X509Certificate) buildXMLObject(X509Certificate.DEFAULT_ELEMENT_NAME);

        String value;
        try {
            value = org.apache.xml.security.utils.Base64.encode(((X509CredentialImpl) cred).getSigningCert().getEncoded());
        } catch (CertificateEncodingException e) {
            throw IdentityException.error("Error occurred while retrieving encoded cert", e);
        }

        cert.setValue(value);
        data.getX509Certificates().add(cert);
        keyInfo.getX509Datas().add(data);

        encrypted.getEncryptedData().getKeyInfo().getEncryptedKeys().get(0).setKeyInfo(keyInfo);
        return encrypted;
    }

    /**
     * Builds SAML Elements
     *
     * @param objectQName
     * @return
     * @throws IdentityException
     */
    private XMLObject buildXMLObject(QName objectQName) throws IdentityException {
        XMLObjectBuilder builder =
                org.opensaml.xml.Configuration.getBuilderFactory()
                        .getBuilder(objectQName);
        if (builder == null) {
            throw IdentityException.error("Unable to retrieve builder for object QName " +
                    objectQName);
        }
        return builder.buildObject(objectQName.getNamespaceURI(), objectQName.getLocalPart(),
                objectQName.getPrefix());
    }
}
