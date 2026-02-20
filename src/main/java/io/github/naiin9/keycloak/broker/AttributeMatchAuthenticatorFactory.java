/*
 * Copyright 2026 naiin9 (https://github.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.github.naiin9.keycloak.broker;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class AttributeMatchAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "idp-attribute-match-authenticator";
    
    public static final String CONF_MATCHING_RULES = "matching.rules";
    public static final String CONF_HASH_SALT = "idp.hash.salt";
    public static final String CONF_DEBUG_LOG = "debug.logging.enabled";

    @Override
    public String getDisplayType() { 
        return "IdP Attribute Match Authenticator (Multi-Field)"; 
    }

    @Override
    public String getReferenceCategory() { 
        return "idp-link"; 
    }

    @Override
    public boolean isConfigurable() { 
        return true; 
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public boolean isUserSetupAllowed() { return false; }

    @Override
    public String getHelpText() { 
        return "Automatically links an IdP user to local user using multiple attributes. Logic: AND (All fields must match)."; 
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> configProperties = new ArrayList<>();

        ProviderConfigProperty rules = new ProviderConfigProperty();
        rules.setName(CONF_MATCHING_RULES);
        rules.setLabel("Matching Rules (CSV or Newline)");
        rules.setHelpText("Format: idp_attr:user_attr:hash(true/false). Example: citizen_id:cid:true, email:email. (Default hash is false)");
        rules.setHelpText("Format: 'idp_attr:user_attr:hash'. " +
                        "Example: 'citizen_id:cid:true, email:email'. " +
                        "Default hash is false if not specified. ");
        rules.setType(ProviderConfigProperty.STRING_TYPE);
        rules.setDefaultValue("identification_no:identification_no:true");
        configProperties.add(rules);

        ProviderConfigProperty hashSalt = new ProviderConfigProperty();
        hashSalt.setName(CONF_HASH_SALT);
        hashSalt.setLabel("Hash Salt");
        hashSalt.setHelpText("Secret salt for hashing. If empty, system environment IDP_LINKER_HASH_SALT will be used.");
        hashSalt.setType(ProviderConfigProperty.PASSWORD);
        configProperties.add(hashSalt);

        ProviderConfigProperty debugLog = new ProviderConfigProperty();
        debugLog.setName(CONF_DEBUG_LOG);
        debugLog.setLabel("Enable Debug Logging");
        debugLog.setHelpText("Print debug information to the server log.");
        debugLog.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        debugLog.setDefaultValue("false");
        configProperties.add(debugLog);

        return configProperties;
    }

    @Override
    public Authenticator create(KeycloakSession session) { 
        return new AttributeMatchAuthenticator(); 
    }

    @Override
    public void init(Config.Scope config) {}
    @Override
    public void postInit(KeycloakSessionFactory factory) {}
    @Override
    public void close() {}
    @Override
    public String getId() { return PROVIDER_ID; }
}