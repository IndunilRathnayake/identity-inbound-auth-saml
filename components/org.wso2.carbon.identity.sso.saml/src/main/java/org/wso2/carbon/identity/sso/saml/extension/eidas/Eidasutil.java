package org.wso2.carbon.identity.sso.saml.extension.eidas;

import java.util.HashMap;
import java.util.Map;

public class Eidasutil {

    public static final Map<String, RequestedAttribute> mandatoryNaturalPerson;
    public static final Map<String, RequestedAttribute> mandatoryLegalPerson;
    static
    {
        mandatoryNaturalPerson = new HashMap<>();
        mandatoryNaturalPerson.put("http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier",
                new RequestedAttribute("http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier",
                        "PersonIdentifier", true));
        mandatoryNaturalPerson.put("http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName",
                new RequestedAttribute("http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName",
                        "FamilyName", true));
        mandatoryNaturalPerson.put("http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName",
                new RequestedAttribute("http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName",
                        "FirstName", true));
        mandatoryNaturalPerson.put("http://eidas.europa.eu/attributes/naturalperson/DateOfBirth",
                new RequestedAttribute("http://eidas.europa.eu/attributes/naturalperson/DateOfBirth",
                        "DateOfBirth", true));

        mandatoryLegalPerson = new HashMap<>();
        mandatoryLegalPerson.put("http://eidas.europa.eu/attributes/legalperson/LegalPersonIdentifier",
                new RequestedAttribute("http://eidas.europa.eu/attributes/legalperson/LegalPersonIdentifier",
                        "LegalPersonIdentifier", true));
        mandatoryLegalPerson.put("http://eidas.europa.eu/attributes/legalperson/LegalName",
                new RequestedAttribute("http://eidas.europa.eu/attributes/legalperson/LegalName",
                        "LegalName", true));
    }
}
