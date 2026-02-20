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
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.AuthenticatorConfigModel;

import jakarta.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class AttributeMatchAuthenticator extends AbstractIdpAuthenticator {

    private static final Logger logger = Logger.getLogger(AttributeMatchAuthenticator.class);

    @Override
    protected void authenticateImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();

        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        Map<String, String> config = (configModel != null) ? configModel.getConfig() : null;

        if (config == null || config.get(AttributeMatchAuthenticatorFactory.CONF_MATCHING_RULES) == null) {
            logger.warn(">>> [Linker] No configuration found. Skipping authenticator.");
            context.attempted();
            return;
        }

        String salt = getSalt(context);
        boolean debugEnabled = Boolean.parseBoolean(config.get(AttributeMatchAuthenticatorFactory.CONF_DEBUG_LOG));
        String rulesRaw = config.get(AttributeMatchAuthenticatorFactory.CONF_MATCHING_RULES);
        
        String[] ruleEntries = rulesRaw.split("[,\\n]");
        Stream<UserModel> userStream = null;

        try {
            for (String entry : ruleEntries) {
                String trimmedEntry = entry.trim();
                if (trimmedEntry.isEmpty()) continue;

                String[] parts = trimmedEntry.split(":");
                
                if (parts.length < 2) {
                    logger.errorf(">>> [Linker Error] Invalid configuration format at '%s'. Expected 'idp:user:hash'", trimmedEntry);
                    context.failure(AuthenticationFlowError.INTERNAL_ERROR);
                    return;
                }
                
                String idpKey = parts[0].trim();
                String userKey = parts[1].trim();

                if (idpKey.isEmpty() || userKey.isEmpty()) {
                    logger.errorf(">>> [Linker Error] Keys cannot be empty in rule '%s'", trimmedEntry);
                    context.failure(AuthenticationFlowError.INTERNAL_ERROR);
                    return ;
                }

                boolean shouldHash = (parts.length >= 3) && "true".equalsIgnoreCase(parts[2].trim());

                List<String> idpValues = brokerContext.getAttributes().get(idpKey);
                String valueFromIdp = (idpValues != null && !idpValues.isEmpty()) ? idpValues.get(0).toString() : null;

                if (valueFromIdp == null || valueFromIdp.isEmpty()) {
                    if (debugEnabled) logger.warnf(">>> [Linker Debug] Attribute [%s] not found in IdP response. Skipping.", idpKey);
                    context.attempted();
                    return;
                }
                
                if (debugEnabled) logger.warnf(">>> [Linker Debug] Original idP with %s = %s", idpKey, valueFromIdp);

                String matchValue = shouldHash ? hashValue(valueFromIdp, salt) : valueFromIdp;
                
                if(debugEnabled) logger.warnf(">>> [Linker Debug] %ssearch user with %s = %s", (userStream == null ? "" : "and "), userKey, matchValue);

                if (userStream == null) {
                    // Rule #1: Search using Database
                    UserModel foundUser = null;


                    if (UserModel.EMAIL.equalsIgnoreCase(userKey)) {
                        foundUser = session.users().getUserByEmail(realm, matchValue);
                    } else if (UserModel.USERNAME.equalsIgnoreCase(userKey)) {
                        foundUser = session.users().getUserByUsername(realm, matchValue);
                    }
                    if(foundUser != null) {
                        userStream = Stream.of(foundUser);
                    } else {

                        List<UserModel> firstMatch = session.users()
                                .searchForUserByUserAttributeStream(realm, userKey, matchValue)
                                .collect(Collectors.toList());
                        
                        if (firstMatch.isEmpty()) {
                            if (debugEnabled) logger.warnf(">>> [Linker Debug] No user found with %s = %s. Stopping.", userKey, matchValue);
                            context.failure(AuthenticationFlowError.UNKNOWN_USER, 
                                context.form().setError("idp-linker-no-user-found").createErrorPage(Response.Status.FORBIDDEN));
                            return; 
                        }

                        userStream = firstMatch.stream();
                    }
                } else {
                    // Rule #n: Filter in memory from previous results
                    List<UserModel> filteredMatch = userStream
                            .filter(u -> matchValue.equals(u.getFirstAttribute(userKey)))
                            .collect(Collectors.toList());

                    if (filteredMatch.isEmpty()) {
                        if (debugEnabled) logger.warnf(">>> [Linker Debug] Subsequent rule failed: %s = %s. No users left. Stopping.", userKey, matchValue);
                        context.failure(AuthenticationFlowError.UNKNOWN_USER, 
                            context.form().setError("idp-linker-data-mismatch").createErrorPage(Response.Status.FORBIDDEN));
                        return;
                    }
                    userStream = filteredMatch.stream();
                }
            }

            List<UserModel> matchedUsers = (userStream != null) ? userStream.collect(Collectors.toList()) : new java.util.ArrayList<>();

            handleMatchResult(context, matchedUsers, debugEnabled);

        } catch (Exception e) {
            logger.error(">>> [Linker Error] Unexpected error during attribute matching", e);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
        }
    }

    private void handleMatchResult(AuthenticationFlowContext context, List<UserModel> users, boolean debug) {
        if (users.size() == 1) {
            UserModel existingUser = users.get(0);
            if (debug) logger.infof(">>> [Linker Debug] Exactly one user matched: %s", existingUser.getUsername());
            context.setUser(existingUser);
            context.getAuthenticationSession().setAuthNote("POST_BROKER_LOGIN_AUTHENTICATED", "true");
            context.success();
        } else if (users.size() > 1) {
            if (debug) logger.errorf(">>> [Linker Debug] Multiple users (%d) matched the criteria. Possible data inconsistency.", users.size());
            context.failure(AuthenticationFlowError.INTERNAL_ERROR, 
                context.form().setError("idp-linker-multiple-users-found").createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
        } else {
            if (debug) logger.warn(">>> [Linker Debug] No user matched all criteria.");
            context.failure(AuthenticationFlowError.UNKNOWN_USER, 
                context.form().setError("idp-linker-no-user-found").createErrorPage(Response.Status.FORBIDDEN));
        }
    }

    private String getSalt(AuthenticationFlowContext context) {
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        if (configModel != null && configModel.getConfig() != null) {
            String uiSalt = configModel.getConfig().get(AttributeMatchAuthenticatorFactory.CONF_HASH_SALT);
            if (uiSalt != null && !uiSalt.isEmpty()) return uiSalt;
        }
        String envSalt = System.getenv("IDP_LINKER_HASH_SALT");
        if (envSalt != null && !envSalt.isEmpty()) return envSalt;
        
        logger.error("!!! CRITICAL: Hash Salt is not configured. Using fallback (Not Secure) !!!");
        return "DEFAULT_UNSAFE_SALT_CHANGE_ME";
    }

    private String hashValue(String value, String salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest((value + salt).getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Error hashing value", e);
        }
    }

    @Override protected void actionImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) { }
    @Override public boolean requiresUser() { return false; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) { }
}