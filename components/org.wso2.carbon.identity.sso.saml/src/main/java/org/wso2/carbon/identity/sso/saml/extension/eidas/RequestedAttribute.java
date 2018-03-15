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

/**
 * The Interface RequestedAttribute.
 *
 * @author fjquevedo
 */
public class RequestedAttribute {

    private String name;
    private String nameFormat;
    private String friednlyName;
    private boolean isRequired;

    public RequestedAttribute(String name, String friendlyName, boolean isRequired) {
        this.name = name;
        this.friednlyName = friendlyName;
        this.isRequired = isRequired;
    }

    public String getFriednlyName() {
        return friednlyName;
    }

    public void setFriednlyName(String friednlyName) {
        this.friednlyName = friednlyName;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getNameFormat() {
        return nameFormat;
    }

    public void setNameFormat(String nameFormat) {
        this.nameFormat = nameFormat;
    }

    public boolean isRequired() {
        return isRequired;
    }

    public void setRequired(boolean isRequired) {
        this.isRequired = isRequired;
    }
}

