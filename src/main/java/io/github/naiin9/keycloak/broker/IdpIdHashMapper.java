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

import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class IdpIdHashMapper extends AbstractIdentityProviderMapper {

    public static final String PROVIDER_ID = "idp-id-privacy-hash-mapper";
    private static final Logger logger = Logger.getLogger(IdpIdHashMapper.class);

    public static final String CONF_HASH_SALT = "idp.hash.salt";
    public static final String CONF_DEBUG_LOG = "debug.logging.enabled";

    @Override
    public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String originalId = context.getId();
        if (originalId == null) return;

        boolean debugEnabled = Boolean.parseBoolean(mapperModel.getConfig().get(CONF_DEBUG_LOG));
        
        if (debugEnabled) logger.infof(">>> [Privacy Hash] Processing original IdP subject: %s", originalId);

        String salt = mapperModel.getConfig().get(CONF_HASH_SALT);
        if (salt == null || salt.isEmpty()) {
            salt = System.getenv("IDP_LINKER_HASH_SALT");
            if (salt == null || salt.isEmpty()) {
                logger.error("!!! CRITICAL: Hash Salt is not configured. Using fallback (Not Secure) !!!");
                salt = "DEFAULT_UNSAFE_SALT_CHANGE_ME";
            }
        }

        String hashedId = hashValue(originalId, salt);

        if (debugEnabled) logger.infof(">>> [Privacy Hash] Hashed subject: %s", hashedId);
        
        context.setId(hashedId);
        context.setUsername(hashValue(context.getUsername(), salt));
    }

    private String hashValue(String value, String salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest((value + salt).getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            logger.error("Error hashing IdP subject", e);
            return value;
        }
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> configProperties = new ArrayList<>();

        ProviderConfigProperty hashSalt = new ProviderConfigProperty();
        hashSalt.setName(CONF_HASH_SALT);
        hashSalt.setLabel("Hash Salt");
        hashSalt.setHelpText("Secret salt for hashing. Must match the salt in Authenticator. If empty, IDP_LINKER_HASH_SALT env will be used.");
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
    public String getDisplayType() { 
        return "IdP ID Privacy Hasher"; 
    }

    @Override
    public String getDisplayCategory() { 
        return "Preprocessor"; 
    }

    @Override
    public String getHelpText() { 
        return "Hashes the IdP Subject (sub) to protect PII in the federated identity table for PDPA compliance."; 
    }

    @Override
    public String[] getCompatibleProviders() { 
        return new String[]{"*"}; 
    }

    @Override
    public String getId() { 
        return PROVIDER_ID; 
    }
}
