/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.application.authenticator.mosip;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.owasp.encoder.Encode;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.application.authenticator.mosip.constant.MOSIPAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.mosip.constant.MOSIPErrorConstants;
import org.wso2.carbon.identity.application.authenticator.mosip.exception.MOSIPAuthenticationException;
import org.wso2.carbon.identity.application.authenticator.mosip.internal.MOSIPAuthenticatorServiceDataHolder;
import org.wso2.carbon.identity.application.authenticator.mosip.dto.MOSIPKycAuthResponseDTO;
import org.wso2.carbon.identity.application.authenticator.mosip.dto.MOSIPKycExchangeResponseDTO;
import org.wso2.carbon.identity.application.authenticator.mosip.dto.MOSIPSendOtpResponseDTO;
import org.wso2.carbon.identity.application.authenticator.mosip.service.MOSIPAuthService;
import org.wso2.carbon.identity.application.authenticator.mosip.util.KeyStoreManager;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Authenticator to authenticate users with MOSIP Identity Authentication (IDA) service.
 */
public class MOSIPAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(MOSIPAuthenticator.class);
    private final MOSIPAuthService mosipAuthService;

    public MOSIPAuthenticator() {

        this.mosipAuthService = MOSIPAuthenticatorServiceDataHolder.getInstance().getMosipAuthService();
    }

    public MOSIPAuthenticator(MOSIPAuthService mosipAuthService) {

        this.mosipAuthService = mosipAuthService;
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {

        return StringUtils.isNotEmpty(request.getParameter(MOSIPAuthenticatorConstants.UIN)) ||
                StringUtils.isNotEmpty(request.getParameter(MOSIPAuthenticatorConstants.OTP));
    }

    @Override
    public void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationContext context) throws AuthenticationFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        validateAuthenticatorProperties(authenticatorProperties);

        // Initialize KeyStoreManager with authenticator properties from deployment.toml
        // Use getAuthenticatorConfig().getParameterMap() to access the configuration values set in deployment.toml
        KeyStoreManager.getInstance(getAuthenticatorConfig().getParameterMap());

        String transactionId = MOSIPAuthService.generateTransactionId();
        context.setProperty(MOSIPAuthenticatorConstants.TRANSACTION_ID, transactionId);

        redirectToMosipLoginPage(request, response, context);
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        String uinFromRequest = request.getParameter(MOSIPAuthenticatorConstants.UIN);
        String otpFromRequest = request.getParameter(MOSIPAuthenticatorConstants.OTP);

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        validateAuthenticatorProperties(authenticatorProperties);

        String baseUrl = authenticatorProperties.get(MOSIPAuthenticatorConstants.BASE_URL);
        String mispLK = authenticatorProperties.get(MOSIPAuthenticatorConstants.MISP_LICENSE_KEY);
        String partnerId = authenticatorProperties.get(MOSIPAuthenticatorConstants.PARTNER_ID);
        String oidcClientId = authenticatorProperties.get(MOSIPAuthenticatorConstants.OIDC_CLIENT_ID);
        String environment = authenticatorProperties.get(MOSIPAuthenticatorConstants.ENV);
        String domainUri = authenticatorProperties.get(MOSIPAuthenticatorConstants.DOMAIN_URI);

        if (StringUtils.isEmpty(environment)) {
            environment = MOSIPAuthenticatorConstants.DEFAULT_ENVIRONMENT;
        }

        String transactionId = (String) context.getProperty(MOSIPAuthenticatorConstants.TRANSACTION_ID);
        if (StringUtils.isEmpty(transactionId)) {
            transactionId = MOSIPAuthService.generateTransactionId();
            context.setProperty(MOSIPAuthenticatorConstants.TRANSACTION_ID, transactionId);
            log.debug("Generated new Transaction ID in processAuthenticationResponse: " + transactionId);
        }

        if (StringUtils.isNotEmpty(uinFromRequest) && StringUtils.isEmpty(otpFromRequest)) {
            processUinSubmission(uinFromRequest, baseUrl, mispLK, partnerId, oidcClientId, domainUri,
                    transactionId, request, response, context);
        } else if (StringUtils.isNotEmpty(otpFromRequest)) {
            processOtpSubmission(otpFromRequest, baseUrl, mispLK, partnerId, oidcClientId, environment,
                    domainUri, transactionId, request, response, context);
        } else {
            throw new AuthenticationFailedException(MOSIPErrorConstants.INVALID_PARAMETER,
                    "Invalid authentication state: UIN or OTP parameters missing as expected.");
        }
    }

    private void processUinSubmission(String uin, String baseUrl, String mispLK, String partnerId,
                                      String oidcClientId, String domainUri, String transactionId, HttpServletRequest request,
                                      HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        context.setProperty(MOSIPAuthenticatorConstants.UIN, uin);
        try {
            MOSIPSendOtpResponseDTO otpResponse = mosipAuthService.sendOtp(
                    baseUrl, mispLK, partnerId, oidcClientId,
                    uin, Arrays.asList(MOSIPAuthenticatorConstants.OTP_CHANNELS), transactionId, domainUri);

            if (otpResponse.getResponse() != null) {
                redirectToOtpInputPage(uin, request, response, context);
                context.setProperty(FrameworkConstants.REQ_ATTR_HANDLED, true);
            } else {
                log.error("Failed to send OTP. Response indicates failure.");
                throw new AuthenticationFailedException(MOSIPErrorConstants.OTP_ERROR,
                        "Failed to send OTP. Please try again later.");
            }
        } catch (MOSIPAuthenticationException e) {
            log.error("Failed to send OTP: " + e.getMessage(), e);
            throw new AuthenticationFailedException(e.getErrorCode(),
                    "Failed to send OTP: " + e.getMessage(), e);
        }
    }

    private void processOtpSubmission(String otp, String baseUrl, String mispLK, String partnerId,
                                      String oidcClientId, String environment, String domainUri,
                                      String transactionId, HttpServletRequest request,
                                      HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        String uinFromContext = (String) context.getProperty(MOSIPAuthenticatorConstants.UIN);

        if (StringUtils.isEmpty(uinFromContext)) {
            throw new AuthenticationFailedException(MOSIPErrorConstants.MISSING_PARAMETER,
                    "UIN is missing from context. Authentication flow error.");
        }

        try {
            MOSIPKycAuthResponseDTO authResponse = mosipAuthService.authenticate(
                    baseUrl, mispLK, partnerId, oidcClientId, uinFromContext, otp,
                    transactionId, environment, domainUri);

            String kycToken = extractKycToken(authResponse);
            if (kycToken == null) {
                throw new AuthenticationFailedException(MOSIPErrorConstants.KYC_ERROR,
                        "MOSIP authentication failed: KYC Token not found in response.");
            }

            AuthenticatedUser authenticatedUser = AuthenticatedUser
                    .createFederateAuthenticatedUserFromSubjectIdentifier(uinFromContext);
            context.setSubject(authenticatedUser);

            List<String> consentClaims = extractClaimsFromIdpConfig(context);

            MOSIPKycExchangeResponseDTO kycExchangeResponse = mosipAuthService.kycExchange(
                    baseUrl, mispLK, partnerId, oidcClientId, uinFromContext, kycToken,
                    consentClaims, transactionId, environment, domainUri);

            processKycExchangeResponse(kycExchangeResponse, authenticatedUser, context);

        } catch (MOSIPAuthenticationException e) {
            log.error("MOSIP Authentication failed: " + e.getMessage(), e);
            throw new AuthenticationFailedException(e.getErrorCode(),
                    "Authentication failed: " + e.getMessage(), e);
        } catch (IOException e) {
            log.error("Network or IO error during authentication: " + e.getMessage(), e);
            throw new AuthenticationFailedException(MOSIPErrorConstants.NETWORK_ERROR,
                    "Network or IO error during authentication.", e);
        }
    }

    private List<String> extractClaimsFromIdpConfig(AuthenticationContext context) {

        List<String> consentClaims = new ArrayList<>();
        ClaimMapping[] claimMappings = context.getExternalIdP().getClaimMappings();

        if (claimMappings != null) {
            for (ClaimMapping mapping : claimMappings) {
                if (mapping != null && mapping.getRemoteClaim() != null &&
                        mapping.getRemoteClaim().getClaimUri() != null) {
                    consentClaims.add(mapping.getRemoteClaim().getClaimUri());
                }
            }
        }

        if (log.isDebugEnabled() && !consentClaims.isEmpty()) {
            log.debug("Extracted " + consentClaims.size() + " claims from IdP configuration");
        }

        return consentClaims;
    }

    private String extractKycToken(MOSIPKycAuthResponseDTO mosipResponse) {

        if (mosipResponse == null) {
            return null;
        }

        if (mosipResponse.getResponse() != null) {
            MOSIPKycAuthResponseDTO.ResponseData responseField = mosipResponse.getResponse();
            return responseField.getKycToken();
        }
        return null;
    }

    private void processKycExchangeResponse(MOSIPKycExchangeResponseDTO kycExchangeResponse,
                                            AuthenticatedUser authenticatedUser,
                                            AuthenticationContext context)
            throws AuthenticationFailedException {

        String encryptedKyc = null;
        String decodedPayload = null;

        if (kycExchangeResponse != null && kycExchangeResponse.getResponse() != null) {
            encryptedKyc = kycExchangeResponse.getResponse().getEncryptedKyc();

            if (StringUtils.isNotEmpty(encryptedKyc)) {
                try {
                    String[] jwtParts = encryptedKyc.split("\\.");
                    if (jwtParts.length > 1) {
                        String payloadBase64Url = jwtParts[1];
                        byte[] decodedPayloadBytes = Base64.getUrlDecoder().decode(payloadBase64Url);
                        decodedPayload = new String(decodedPayloadBytes, StandardCharsets.UTF_8);
                    }
                } catch (Exception e) {
                    log.error("Error decoding KYC JWT payload: " + e.getMessage(), e);
                    throw new AuthenticationFailedException(MOSIPErrorConstants.KYC_ERROR,
                            "Error processing KYC data", e);
                }
            }
        }

        if (StringUtils.isNotEmpty(decodedPayload)) {
            Map<ClaimMapping, String> claims = buildClaimMappings(context, decodedPayload);
            if (claims != null && !claims.isEmpty()) {
                authenticatedUser.setUserAttributes(claims);
            }
        } else {
            log.warn("Could not extract KYC data payload from response");
        }
    }

    /**
     * Build claim mappings from KYC data
     *
     * @param context    The authentication context
     * @param decodedKyc The decoded KYC data as JSON string
     * @return Map of claim mappings
     * @throws AuthenticationFailedException If claim mapping fails
     */
    private Map<ClaimMapping, String> buildClaimMappings(AuthenticationContext context, String decodedKyc)
            throws AuthenticationFailedException {

        if (StringUtils.isEmpty(decodedKyc)) {
            log.warn("Decoded KYC data is empty. Cannot build claim mappings.");
            return Collections.emptyMap();
        }

        JSONObject kycData;
        try {
            kycData = new JSONObject(decodedKyc);
        } catch (JSONException e) {
            log.error("Error parsing decoded KYC JSON", e);
            throw new AuthenticationFailedException("Failed to parse KYC data. Invalid JSON format.", e);
        }

        Map<ClaimMapping, String> claims = new HashMap<>();
        ClaimMapping[] claimMappings = context.getExternalIdP().getClaimMappings();

        if (claimMappings == null || claimMappings.length == 0) {
            if (log.isDebugEnabled()) {
                log.debug("No claim mappings configured for the Identity Provider.");
            }
            return claims;
        }

        for (ClaimMapping mapping : claimMappings) {
            if (mapping == null ||
                    mapping.getRemoteClaim() == null ||
                    mapping.getLocalClaim() == null ||
                    StringUtils.isEmpty(mapping.getRemoteClaim().getClaimUri())) {
                continue;
            }

            String remoteClaimUri = mapping.getRemoteClaim().getClaimUri();

            if (kycData.has(remoteClaimUri)) {
                Object claimValue = kycData.opt(remoteClaimUri);

                if (claimValue != null && claimValue != JSONObject.NULL) {
                    String strClaimValue = claimValue instanceof String ?
                            (String) claimValue : String.valueOf(claimValue);

                    if (StringUtils.isNotEmpty(strClaimValue)) {
                        claims.put(mapping, strClaimValue);
                    }
                }
            }
        }

        return claims;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }

        String uin = request.getParameter(MOSIPAuthenticatorConstants.UIN);
        String otp = request.getParameter(MOSIPAuthenticatorConstants.OTP);

        // Case 1: UIN is submitted, OTP is not yet submitted.
        if (StringUtils.isNotEmpty(uin) && StringUtils.isEmpty(otp)) {
            processAuthenticationResponse(request, response, context);
            return AuthenticatorFlowStatus.INCOMPLETE; // Flow is incomplete, waiting for OTP.
        }
        // Case 2: OTP is submitted.
        else if (StringUtils.isNotEmpty(otp)) {
            processAuthenticationResponse(request, response, context);
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED; // Flow is complete.
        }
        // Case 3: Neither UIN nor OTP is present in the request parameters.
        else {
            initiateAuthenticationRequest(request, response, context);
            return AuthenticatorFlowStatus.INCOMPLETE;
        }
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return request.getParameter(MOSIPAuthenticatorConstants.SESSION_DATA_KEY);
    }

    @Override
    public String getFriendlyName() {

        return MOSIPAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {

        return MOSIPAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();
        int parameterCount = 0;

        Property baseUrl = new Property();
        baseUrl.setName(MOSIPAuthenticatorConstants.BASE_URL);
        baseUrl.setDisplayName("Base URL");
        baseUrl.setRequired(true);
        baseUrl.setDescription("Enter the base URL of the MOSIP IDA service");
        baseUrl.setDisplayOrder(++parameterCount);
        configProperties.add(baseUrl);

        Property mispLK = new Property();
        mispLK.setName(MOSIPAuthenticatorConstants.MISP_LICENSE_KEY);
        mispLK.setDisplayName("MISP License Key");
        mispLK.setRequired(true);
        mispLK.setDescription("Enter the MISP license key");
        mispLK.setDisplayOrder(++parameterCount);
        configProperties.add(mispLK);

        Property partnerId = new Property();
        partnerId.setName(MOSIPAuthenticatorConstants.PARTNER_ID);
        partnerId.setDisplayName("Partner ID");
        partnerId.setRequired(true);
        partnerId.setDescription("Enter the partner ID");
        partnerId.setDisplayOrder(++parameterCount);
        configProperties.add(partnerId);

        Property oidcClientId = new Property();
        oidcClientId.setName(MOSIPAuthenticatorConstants.OIDC_CLIENT_ID);
        oidcClientId.setDisplayName("OIDC Client ID");
        oidcClientId.setRequired(true);
        oidcClientId.setDescription("Enter the OIDC client ID (API Key for MOSIP)");
        oidcClientId.setDisplayOrder(++parameterCount);
        configProperties.add(oidcClientId);

        Property env = new Property();
        env.setName(MOSIPAuthenticatorConstants.ENV);
        env.setDisplayName("Environment");
        env.setRequired(false);
        env.setDescription("Enter the environment (e.g., Staging, Production). Defaults to 'Staging'.");
        env.setDisplayOrder(++parameterCount);
        configProperties.add(env);

        Property domainUri = new Property();
        domainUri.setName(MOSIPAuthenticatorConstants.DOMAIN_URI);
        domainUri.setDisplayName("Domain URI");
        domainUri.setRequired(true);
        domainUri.setDescription("Enter the domain URI for the MOSIP ID Authentication service");
        domainUri.setDisplayOrder(++parameterCount);
        configProperties.add(domainUri);

        return configProperties;
    }

    /**
     * Redirects to the MOSIP login page
     *
     * @param request  HttpServletRequest
     * @param response HttpServletResponse
     * @param context  Authentication context
     * @throws AuthenticationFailedException If an error occurs during redirection
     */
    private void redirectToMosipLoginPage(HttpServletRequest request, HttpServletResponse response,
                                          AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            String loginPage = ServiceURLBuilder.create()
                    .addPath(MOSIPAuthenticatorConstants.MOSIP_LOGIN_PAGE)
                    .build()
                    .getAbsolutePublicURL();

            // Get query parameters from context
            String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                    context.getCallerSessionKey(), context.getContextIdentifier());

            // Get multiOptionURI parameter from the request
            String multiOptionURI = getMultiOptionURIQueryString(request);

            // Build URL with query parameters
            StringBuilder urlBuilder = new StringBuilder(loginPage);

            // Add query parameters if they exist
            if (StringUtils.isNotEmpty(queryParams)) {
                if (!queryParams.startsWith("?")) {
                    urlBuilder.append("?");
                }
                urlBuilder.append(queryParams);

                // Add the authenticator parameter if query params already exist
                urlBuilder.append("&authenticators=").append(getName());
            } else {
                // Start with ? if no query params exist yet
                urlBuilder.append("?authenticators=").append(getName());
            }

            // Add multiOptionURI if available
            if (StringUtils.isNotEmpty(multiOptionURI)) {
                urlBuilder.append(multiOptionURI);
            }

            // Add any framework context parameters that might not be included in queryParams
            String contextParams = context.getContextIdIncludedQueryParams();
            if (StringUtils.isNotEmpty(contextParams) && !queryParams.contains(contextParams)) {
                if (!contextParams.startsWith("&")) {
                    urlBuilder.append("&");
                }
                urlBuilder.append(contextParams);
            }

            // Add retry parameter and error message if the context is retrying
            if (context.isRetrying()) {
                // Get the error details
                String errorCode = (String) context.getProperty(MOSIPAuthenticatorConstants.ERROR_CODE);
                String errorMsg = getRetryErrorMessage(errorCode);

                // Add retry parameters
                urlBuilder.append(MOSIPAuthenticatorConstants.RETRY_PARAM);

                if (StringUtils.isNotEmpty(errorMsg)) {
                    urlBuilder.append("&").append(MOSIPAuthenticatorConstants.ERROR_MESSAGE)
                            .append("=").append(Encode.forUriComponent(errorMsg));
                }

                // Log retry details
                String transactionId = (String) context.getProperty(MOSIPAuthenticatorConstants.TRANSACTION_ID);
                log.warn(String.format("[Transaction ID: %s] Authentication is retrying with error code: %s",
                        transactionId, errorCode));
            }

            String url = urlBuilder.toString();

            if (log.isDebugEnabled()) {
                String transactionId = (String) context.getProperty(MOSIPAuthenticatorConstants.TRANSACTION_ID);
                log.debug(String.format("[Transaction ID: %s] Redirecting to MOSIP login page: %s",
                        transactionId, url));
            }

            response.sendRedirect(url);

        } catch (IOException | URLBuilderException e) {
            String transactionId = (String) context.getProperty(MOSIPAuthenticatorConstants.TRANSACTION_ID);
            log.error(String.format("[Transaction ID: %s] Error while redirecting to MOSIP login page: %s",
                    transactionId, e.getMessage()), e);

            throw new AuthenticationFailedException("Error while redirecting to MOSIP login page", e);
        }
    }

    /**
     * Get user-friendly error message for retry scenarios based on error code
     *
     * @param errorCode The error code
     * @return User-friendly error message
     */
    private String getRetryErrorMessage(String errorCode) {

        if (StringUtils.isEmpty(errorCode)) {
            return MOSIPErrorConstants.USER_FRIENDLY_GENERAL_ERROR;
        }

        switch (errorCode) {
            case MOSIPErrorConstants.OTP_INVALID:
            case MOSIPErrorConstants.OTP_EXPIRED:
                return MOSIPErrorConstants.USER_FRIENDLY_OTP_ERROR;

            case MOSIPErrorConstants.NETWORK_ERROR:
            case MOSIPErrorConstants.TIMEOUT_ERROR:
            case MOSIPErrorConstants.HTTP_500:
            case MOSIPErrorConstants.HTTP_503:
                return MOSIPErrorConstants.USER_FRIENDLY_NETWORK_ERROR;

            case MOSIPErrorConstants.CONFIG_ERROR:
            case MOSIPErrorConstants.MISSING_PARAMETER:
            case MOSIPErrorConstants.INVALID_PARAMETER:
                return MOSIPErrorConstants.USER_FRIENDLY_CONFIG_ERROR;

            default:
                return MOSIPErrorConstants.USER_FRIENDLY_GENERAL_ERROR;
        }
    }

    /**
     * Redirects to the MOSIP OTP input page
     *
     * @param uinValue UIN value of the user
     * @param request  HttpServletRequest
     * @param response HttpServletResponse
     * @param context  Authentication context
     * @throws AuthenticationFailedException If an error occurs during redirection
     */
    private void redirectToOtpInputPage(String uinValue, HttpServletRequest request,
                                        HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            String otpPage = ServiceURLBuilder.create()
                    .addPath(MOSIPAuthenticatorConstants.MOSIP_OTP_PAGE)
                    .build()
                    .getAbsolutePublicURL();

            // Get query parameters from context
            String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                    context.getCallerSessionKey(), context.getContextIdentifier());

            // Get multiOptionURI parameter
            String multiOptionURI = getMultiOptionURIQueryString(request);

            // Build URL with query parameters
            StringBuilder urlBuilder = new StringBuilder(otpPage);

            // Add query parameters if they exist
            if (StringUtils.isNotEmpty(queryParams)) {
                if (!queryParams.startsWith("?")) {
                    urlBuilder.append("?");
                }
                urlBuilder.append(queryParams);

                // Add authenticator parameter
                urlBuilder.append("&authenticators=").append(getName());
            } else {
                // Start with ? if no query params exist yet
                urlBuilder.append("?authenticators=").append(getName());
            }

            // Add multiOptionURI if available
            if (StringUtils.isNotEmpty(multiOptionURI)) {
                urlBuilder.append(multiOptionURI);
            }

            // Add the transaction ID to maintain state
            String transactionId = (String) context.getProperty(MOSIPAuthenticatorConstants.TRANSACTION_ID);
            if (StringUtils.isNotEmpty(transactionId)) {
                urlBuilder.append("&").append(MOSIPAuthenticatorConstants.TRANSACTION_ID)
                        .append("=")
                        .append(transactionId);
            }

            // Add UIN if provided
            if (StringUtils.isNotEmpty(uinValue)) {
                urlBuilder.append("&").append(MOSIPAuthenticatorConstants.UIN)
                        .append("=")
                        .append(Encode.forUriComponent(uinValue));
            }
            // If UIN wasn't provided directly but exists in context, add it
            else if (context.getProperty(MOSIPAuthenticatorConstants.UIN) != null) {
                String uin = (String) context.getProperty(MOSIPAuthenticatorConstants.UIN);
                urlBuilder.append("&").append(MOSIPAuthenticatorConstants.UIN)
                        .append("=")
                        .append(Encode.forUriComponent(uin));
            }

            // Add retry parameter and error message if the context is retrying
            if (context.isRetrying() &&
                    !Boolean.parseBoolean(request.getParameter(MOSIPAuthenticatorConstants.RESEND))) {
                // Get the error details
                String errorCode = (String) context.getProperty(MOSIPAuthenticatorConstants.ERROR_CODE);
                String errorMsg = getRetryErrorMessage(errorCode);

                // Add retry parameters
                urlBuilder.append(MOSIPAuthenticatorConstants.RETRY_PARAM);

                if (StringUtils.isNotEmpty(errorMsg)) {
                    urlBuilder.append("&").append(MOSIPAuthenticatorConstants.ERROR_MESSAGE)
                            .append("=").append(Encode.forUriComponent(errorMsg));
                }

                // Log retry details
                log.warn(String.format("[Transaction ID: %s] OTP validation is retrying with error code: %s",
                        transactionId, errorCode));
            }

            // Add resend parameter if the resend button was clicked
            if (Boolean.parseBoolean(request.getParameter(MOSIPAuthenticatorConstants.RESEND))) {
                urlBuilder.append(MOSIPAuthenticatorConstants.RESEND_PARAM);

                if (log.isDebugEnabled()) {
                    log.debug(String.format("[Transaction ID: %s] Resending OTP for UIN", transactionId));
                }
            }

            // Add any framework context parameters that might not be included in queryParams
            String contextParams = context.getContextIdIncludedQueryParams();
            if (StringUtils.isNotEmpty(contextParams) && !queryParams.contains(contextParams)) {
                if (!contextParams.startsWith("&")) {
                    urlBuilder.append("&");
                }
                urlBuilder.append(contextParams);
            }

            String url = urlBuilder.toString();

            if (log.isDebugEnabled()) {
                log.debug(String.format("[Transaction ID: %s] Redirecting to MOSIP OTP page: %s",
                        transactionId, sanitizeUrlForLogging(url)));
            }

            response.sendRedirect(url);
        } catch (IOException | URLBuilderException e) {
            String transactionId = (String) context.getProperty(MOSIPAuthenticatorConstants.TRANSACTION_ID);
            log.error(String.format("[Transaction ID: %s] Error while redirecting to MOSIP OTP input page: %s",
                    transactionId, e.getMessage()), e);

            throw new AuthenticationFailedException("Error while redirecting to MOSIP OTP input page", e);
        }
    }

    /**
     * Sanitize URL for logging to prevent sensitive information disclosure
     *
     * @param url The URL to sanitize
     * @return Sanitized URL
     */
    private String sanitizeUrlForLogging(String url) {

        if (StringUtils.isEmpty(url)) {
            return "";
        }

        // Mask sensitive parameters like UIN, OTP, etc.
        String maskedUrl = url;
        String[] sensitiveParams = {
                MOSIPAuthenticatorConstants.UIN,
                MOSIPAuthenticatorConstants.UIN_PARAM,
                MOSIPAuthenticatorConstants.OTP,
                MOSIPAuthenticatorConstants.MISP_LICENSE_KEY
        };

        for (String param : sensitiveParams) {
            maskedUrl = maskedUrl.replaceAll(
                    "([?&]" + param + "=)[^&]+",
                    "$1***MASKED***"
                                            );
        }

        return maskedUrl;
    }

    /**
     * Validates that the required authenticator properties are present
     *
     * @param authenticatorProperties Map of authenticator properties
     * @throws AuthenticationFailedException If required properties are missing
     */
    private void validateAuthenticatorProperties(Map<String, String> authenticatorProperties)
            throws AuthenticationFailedException {

        String baseUrl = authenticatorProperties.get(MOSIPAuthenticatorConstants.BASE_URL);
        String mispLK = authenticatorProperties.get(MOSIPAuthenticatorConstants.MISP_LICENSE_KEY);
        String partnerId = authenticatorProperties.get(MOSIPAuthenticatorConstants.PARTNER_ID);
        String oidcClientId = authenticatorProperties.get(MOSIPAuthenticatorConstants.OIDC_CLIENT_ID);

        if (StringUtils.isEmpty(baseUrl)) {
            throw new AuthenticationFailedException("Base URL is not configured for the authenticator");
        }
        if (StringUtils.isEmpty(mispLK)) {
            throw new AuthenticationFailedException("MISP License Key is not configured for the authenticator");
        }
        if (StringUtils.isEmpty(partnerId)) {
            throw new AuthenticationFailedException("Partner ID is not configured for the authenticator");
        }
        if (StringUtils.isEmpty(oidcClientId)) {
            throw new AuthenticationFailedException("OIDC Client ID is not configured for the authenticator");
        }
    }

    /**
     * Extract the multiOptionURI query parameter from the request if present
     *
     * @param request The HTTP request
     * @return The multiOptionURI query string or empty string if not present
     */
    private String getMultiOptionURIQueryString(HttpServletRequest request) {

        String multiOptionURI = request.getParameter(MOSIPAuthenticatorConstants.MULTI_OPTION_URI);
        if (StringUtils.isNotEmpty(multiOptionURI)) {
            return MOSIPAuthenticatorConstants.MULTI_OPTION_URI_PARAM + multiOptionURI;
        }
        return "";
    }
}
