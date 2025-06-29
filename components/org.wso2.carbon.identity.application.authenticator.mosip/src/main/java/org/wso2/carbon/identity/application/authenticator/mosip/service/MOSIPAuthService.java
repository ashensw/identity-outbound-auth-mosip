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

package org.wso2.carbon.identity.application.authenticator.mosip.service;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.wso2.carbon.identity.application.authenticator.mosip.client.MOSIPClient;
import org.wso2.carbon.identity.application.authenticator.mosip.constant.MOSIPAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.mosip.constant.MOSIPErrorConstants;
import org.wso2.carbon.identity.application.authenticator.mosip.exception.MOSIPAuthenticationException;
import org.wso2.carbon.identity.application.authenticator.mosip.dto.MOSIPKycAuthRequestDTO;
import org.wso2.carbon.identity.application.authenticator.mosip.dto.MOSIPKycAuthResponseDTO;
import org.wso2.carbon.identity.application.authenticator.mosip.dto.MOSIPKycExchangeRequestDTO;
import org.wso2.carbon.identity.application.authenticator.mosip.dto.MOSIPKycExchangeResponseDTO;
import org.wso2.carbon.identity.application.authenticator.mosip.dto.MOSIPSendOtpRequestDTO;
import org.wso2.carbon.identity.application.authenticator.mosip.dto.MOSIPSendOtpResponseDTO;
import org.wso2.carbon.identity.application.authenticator.mosip.util.CryptoUtil;
import org.wso2.carbon.identity.application.authenticator.mosip.util.KeyStoreManager;

import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service class that implements business logic for MOSIP Identity Authentication (IDA)
 */
public class MOSIPAuthService implements Serializable {

    private static final long serialVersionUID = 13123123123441L;
    private static final Log log = LogFactory.getLog(MOSIPAuthService.class);
    private static final List<String> SUPPORTED_OTP_CHANNELS =
            Collections.unmodifiableList(Arrays.asList("email", "phone"));
    private static final int TRANSACTION_ID_MAX_LENGTH = 10;
    private static final String ALPHANUMERIC_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final Random RANDOM = new Random();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    // Cache for URL normalization to avoid redundant string operations
    private static final ConcurrentHashMap<String, ConcurrentHashMap<String, String>> URL_CACHE =
            new ConcurrentHashMap<>();

    // Default KYC attributes that are common across requests
    private static final List<String> DEFAULT_KYC_ATTRIBUTES = Collections.unmodifiableList(
            Arrays.asList("fullName", "email", "phone", "gender", "dateOfBirth", "address"));

    // Initialize KeyStoreManager just once at class loading time
    static {
        try {
            KeyStoreManager.getInstance();
            if (log.isDebugEnabled()) {
                log.debug("KeyStoreManager initialized at service startup");
            }
        } catch (Exception e) {
            log.error("Error initializing KeyStoreManager during service startup", e);
        }
    }

    private final MOSIPClient mosipClient;

    /**
     * Default constructor
     */
    public MOSIPAuthService() {

        this.mosipClient = new MOSIPClient();
    }

    /**
     * Constructor with client dependency injection for testing
     *
     * @param mosipClient The MOSIP client to use
     */
    public MOSIPAuthService(MOSIPClient mosipClient) {

        this.mosipClient = mosipClient;
    }

    /**
     * Generate a random alphanumeric transaction ID with maximum length of 10 characters
     *
     * @return Random alphanumeric transaction ID
     */
    public static String generateTransactionId() {

        StringBuilder sb = new StringBuilder(TRANSACTION_ID_MAX_LENGTH);
        for (int i = 0; i < TRANSACTION_ID_MAX_LENGTH; i++) {
            sb.append(ALPHANUMERIC_CHARS.charAt(RANDOM.nextInt(ALPHANUMERIC_CHARS.length())));
        }
        return sb.toString();
    }

    /**
     * Normalize URL with caching to avoid redundant string operations
     *
     * @param baseUrl  Base URL
     * @param endpoint Endpoint path
     * @return Normalized URL
     */
    private String normalizeUrl(String baseUrl, String endpoint) {

        ConcurrentHashMap<String, String> endpointCache = URL_CACHE.computeIfAbsent(
                baseUrl, k -> new ConcurrentHashMap<>());

        return endpointCache.computeIfAbsent(endpoint, k -> {
            String normalizedBaseUrl = baseUrl;
            if (normalizedBaseUrl.endsWith("/")) {
                normalizedBaseUrl = normalizedBaseUrl.substring(0, normalizedBaseUrl.length() - 1);
            }

            String normalizedEndpoint = endpoint;
            if (!normalizedEndpoint.startsWith("/")) {
                normalizedEndpoint = "/" + normalizedEndpoint;
            }

            return normalizedBaseUrl + normalizedEndpoint;
        });
    }

    /**
     * Check if an OTP channel is supported
     *
     * @param channel Channel to check
     * @return true if supported, false otherwise
     */
    private boolean isSupportedOtpChannel(String channel) {

        return SUPPORTED_OTP_CHANNELS.contains(channel);
    }

    /**
     * Send OTP to the user's registered channels (email/phone)
     *
     * @param baseUrl       The base URL of the MOSIP IDA service
     * @param mispLK        MISP License Key
     * @param partnerId     Partner ID
     * @param oidcClientId  API Key
     * @param uin           User's UIN
     * @param channels      List of channels to send OTP (email/phone)
     * @param transactionId Transaction ID (optional, will generate if null)
     * @param domainUri     Domain URI
     * @return MOSIPSendOtpResponseDTO with the response
     * @throws MOSIPAuthenticationException If sending OTP fails
     */
    public MOSIPSendOtpResponseDTO sendOtp(String baseUrl, String mispLK, String partnerId, String oidcClientId,
                                           String uin, List<String> channels, String transactionId, String domainUri) throws
            MOSIPAuthenticationException {

        if (log.isDebugEnabled()) {
            log.debug("Sending OTP with transaction ID: " + transactionId);
        }

        try {
            if (StringUtils.isEmpty(transactionId)) {
                transactionId = generateTransactionId();
                if (log.isDebugEnabled()) {
                    log.debug("Generated new transaction ID: " + transactionId);
                }
            } else if (transactionId.length() > TRANSACTION_ID_MAX_LENGTH) {
                transactionId = transactionId.substring(0, TRANSACTION_ID_MAX_LENGTH);
                if (log.isDebugEnabled()) {
                    log.debug("Truncated transaction ID to: " + transactionId);
                }
            }

            MOSIPSendOtpRequestDTO requestDTO = new MOSIPSendOtpRequestDTO();
            requestDTO.setId(MOSIPAuthenticatorConstants.DEFAULT_OTP_ID);
            requestDTO.setVersion(MOSIPAuthenticatorConstants.DEFAULT_AUTH_VERSION);
            requestDTO.setRequestTime(CryptoUtil.getUTCDateTime());
            requestDTO.setTransactionID(transactionId);
            requestDTO.setIndividualId(uin);
            requestDTO.setIndividualIdType(MOSIPAuthenticatorConstants.DEFAULT_ID_TYPE);

            List<String> supportedChannels = new ArrayList<>();
            for (String channel : channels) {
                if (isSupportedOtpChannel(channel)) {
                    supportedChannels.add(channel);
                }
            }
            requestDTO.setOtpChannel(supportedChannels);

            String endpoint = normalizeUrl(baseUrl, MOSIPAuthenticatorConstants.SEND_OTP_ENDPOINT)
                    + "/" + mispLK + "/" + partnerId + "/" + oidcClientId;

            String requestBody = OBJECT_MAPPER.writeValueAsString(requestDTO);
            String signature = CryptoUtil.generateMosipRequestSignatureAuthKey(requestBody);

            Map<String, String> headers = new HashMap<>();
            headers.put(MOSIPAuthenticatorConstants.SIGNATURE_HEADER, signature);
            headers.put(MOSIPAuthenticatorConstants.AUTHORIZATION_HEADER,
                    MOSIPAuthenticatorConstants.AUTHORIZATION_HEADER);

            Map<String, String> requestContext = new HashMap<>();
            requestContext.put(MOSIPAuthenticatorConstants.TRANSACTION_ID, transactionId);

            String responseBody = mosipClient.sendPostRequest(endpoint, requestBody, headers, requestContext);

            MOSIPSendOtpResponseDTO response = OBJECT_MAPPER.readValue(responseBody, MOSIPSendOtpResponseDTO.class);
            if (response.getErrors() != null && !response.getErrors().isEmpty()) {
                MOSIPSendOtpResponseDTO.ErrorData errorData = response.getErrors().get(0);
                throw new MOSIPAuthenticationException(errorData.getErrorCode(), errorData.getErrorMessage());
            }
            return response;
        } catch (Exception e) {
            log.error("Error occurred while sending OTP: " + e.getMessage(), e);
            String errorCode = determineErrorCode(e);
            throw new MOSIPAuthenticationException(errorCode, "Error sending OTP: " + e.getMessage(), e);
        }
    }

    /**
     * Authenticate a user with MOSIP using UIN and OTP
     *
     * @param baseUrl       The base URL of the MOSIP IDA service
     * @param mispLK        MISP License Key
     * @param partnerId     Partner ID
     * @param oidcClientId  API Key
     * @param uin           User's UIN
     * @param otp           OTP entered by the user
     * @param transactionId Transaction ID
     * @param environment   Environment (e.g., Staging, Production)
     * @param domainUri     Domain URI
     * @return MOSIPKycAuthResponseDTO with the response
     * @throws MOSIPAuthenticationException If authentication fails
     * @throws IOException                  If a network error occurs
     */
    public MOSIPKycAuthResponseDTO authenticate(String baseUrl, String mispLK, String partnerId,
                                                String oidcClientId, String uin, String otp,
                                                String transactionId, String environment, String domainUri)
            throws MOSIPAuthenticationException, IOException {

        if (log.isDebugEnabled()) {
            log.debug("Authenticating with transaction ID: " + transactionId);
        }

        try {
            MOSIPKycAuthRequestDTO requestDTO = new MOSIPKycAuthRequestDTO();
            requestDTO.setId(MOSIPAuthenticatorConstants.DEFAULT_KYC_AUTH_ID);
            requestDTO.setVersion(MOSIPAuthenticatorConstants.DEFAULT_AUTH_VERSION);
            requestDTO.setRequestTime(CryptoUtil.getUTCDateTime());
            requestDTO.setTransactionID(transactionId);
            requestDTO.setIndividualId(uin);
            requestDTO.setIndividualIdType(MOSIPAuthenticatorConstants.DEFAULT_ID_TYPE);
            requestDTO.setConsentObtained(true);
            requestDTO.setDomainUri(domainUri);
            requestDTO.setEnv(environment);
            requestDTO.setAllowedKycAttributes(DEFAULT_KYC_ATTRIBUTES);

            MOSIPKycAuthRequestDTO.AuthRequest authRequest = new MOSIPKycAuthRequestDTO.AuthRequest();
            authRequest.setOtp(otp);
            authRequest.setTimestamp(CryptoUtil.getUTCDateTime());

            String authRequestString = OBJECT_MAPPER.writeValueAsString(authRequest);

            CryptoUtil.EncryptedRequestInfo encryptedInfo = CryptoUtil.encryptRequest(authRequestString);

            requestDTO.setRequestHMAC(encryptedInfo.getHmac());
            requestDTO.setRequestSessionKey(encryptedInfo.getEncryptedSessionKey());
            requestDTO.setThumbprint(encryptedInfo.getBase64UrlEncodedThumbprint());
            requestDTO.setRequest(encryptedInfo.getBase64UrlEncodedRequest());

            String endpoint = normalizeUrl(baseUrl, MOSIPAuthenticatorConstants.KYC_AUTH_ENDPOINT)
                    + "/" + mispLK + "/" + partnerId + "/" + oidcClientId;

            String requestBody = OBJECT_MAPPER.writeValueAsString(requestDTO);
            String signature = CryptoUtil.generateMosipRequestSignatureAuthKey(requestBody);

            Map<String, String> headers = new HashMap<>();
            headers.put(MOSIPAuthenticatorConstants.SIGNATURE_HEADER, signature);
            headers.put(MOSIPAuthenticatorConstants.AUTHORIZATION_HEADER,
                    MOSIPAuthenticatorConstants.AUTHORIZATION_HEADER);

            Map<String, String> requestContext = new HashMap<>();
            requestContext.put(MOSIPAuthenticatorConstants.TRANSACTION_ID, transactionId);

            String responseBody = mosipClient.sendPostRequest(endpoint, requestBody, headers, requestContext);
            MOSIPKycAuthResponseDTO authResponse = OBJECT_MAPPER.readValue(responseBody, MOSIPKycAuthResponseDTO.class);
            if (authResponse.getErrors() != null && !authResponse.getErrors().isEmpty()) {
                MOSIPKycAuthResponseDTO.ErrorData errorData = authResponse.getErrors().get(0);
                throw new MOSIPAuthenticationException(errorData.getErrorCode(), errorData.getErrorMessage());
            }
            return authResponse;
        } catch (IOException e) {
            log.error("I/O error during MOSIP authentication: " + e.getMessage(), e);
            throw new MOSIPAuthenticationException(MOSIPErrorConstants.NETWORK_ERROR,
                    "Network error during authentication: " + e.getMessage(), e);
        } catch (Exception e) {
            log.error("Error during MOSIP authentication: " + e.getMessage(), e);
            String errorCode = determineErrorCode(e);
            throw new MOSIPAuthenticationException(errorCode,
                    "Authentication error: " + e.getMessage(), e);
        }
    }

    /**
     * Exchange KYC token for user information
     *
     * @param baseUrl         The base URL of the MOSIP IDA service
     * @param mispLK          MISP License Key
     * @param partnerId       Partner ID
     * @param oidcClientId    API Key
     * @param uin             User's UIN
     * @param kycToken        KYC token received from authentication
     * @param consentedClaims List of claims for which consent is given
     * @param transactionId   Transaction ID
     * @param environment     Environment (e.g., Staging, Production)
     * @param domainUri       Domain URI
     * @return MOSIPKycExchangeResponseDTO with the response
     * @throws MOSIPAuthenticationException If KYC exchange fails
     */
    public MOSIPKycExchangeResponseDTO kycExchange(String baseUrl, String mispLK, String partnerId,
                                                   String oidcClientId, String uin, String kycToken,
                                                   List<String> consentedClaims, String transactionId,
                                                   String environment, String domainUri)
            throws MOSIPAuthenticationException {

        if (log.isDebugEnabled()) {
            log.debug("Exchanging KYC token with transaction ID: " + transactionId);
        }

        try {
            // Create the request DTO
            MOSIPKycExchangeRequestDTO requestDTO = new MOSIPKycExchangeRequestDTO();
            requestDTO.setId(MOSIPAuthenticatorConstants.DEFAULT_KYC_EXCHANGE_ID);
            requestDTO.setVersion(MOSIPAuthenticatorConstants.DEFAULT_AUTH_VERSION);
            requestDTO.setRequestTime(CryptoUtil.getUTCDateTime());
            requestDTO.setTransactionID(transactionId);
            requestDTO.setIndividualId(uin);
            requestDTO.setKycToken(kycToken);
            requestDTO.setConsentObtained(consentedClaims);

            // Add locales - using default locale
            List<String> locales = new ArrayList<>();
            locales.add(MOSIPAuthenticatorConstants.DEFAULT_LOCALE);
            requestDTO.setLocales(locales);

            // Set the response type to JWT as per working example
            requestDTO.setRespType(MOSIPAuthenticatorConstants.RESP_TYPE);

            // Convert DTO to JSON string for request
            ObjectMapper mapper = new ObjectMapper();
            String requestBody = mapper.writeValueAsString(requestDTO);

            // Send request to MOSIP IDA service
            String endpoint = normalizeUrl(baseUrl, MOSIPAuthenticatorConstants.KYC_EXCHANGE_ENDPOINT)
                    + "/" + mispLK + "/" + partnerId + "/" + oidcClientId;

            // Generate signature using CryptoUtil
            String signature = CryptoUtil.generateMosipRequestSignatureAuthKey(requestBody);

            if (log.isDebugEnabled()) {
                log.debug("Sending MOSIP KYC exchange request to: " + endpoint);
            }

            // Set headers and request context
            Map<String, String> headers = new HashMap<>();
            headers.put(MOSIPAuthenticatorConstants.SIGNATURE_HEADER, signature);
            headers.put(MOSIPAuthenticatorConstants.AUTHORIZATION_HEADER,
                    MOSIPAuthenticatorConstants.AUTHORIZATION_HEADER);

            Map<String, String> requestContext = new HashMap<>();
            requestContext.put(MOSIPAuthenticatorConstants.TRANSACTION_ID, transactionId);

            // Send HTTP request
            String responseBody = mosipClient.sendPostRequest(endpoint, requestBody, headers, requestContext);

            MOSIPKycExchangeResponseDTO exchangeResponse =
                    OBJECT_MAPPER.readValue(responseBody, MOSIPKycExchangeResponseDTO.class);
            if (exchangeResponse.getErrors() != null && !exchangeResponse.getErrors().isEmpty()) {
                MOSIPKycExchangeResponseDTO.ErrorData errorData = exchangeResponse.getErrors().get(0);
                throw new MOSIPAuthenticationException(errorData.getErrorCode(), errorData.getErrorMessage());
            }
            return exchangeResponse;
        } catch (Exception e) {
            String errorMsg = "Error occurred during KYC exchange: " + e.getMessage();
            log.error(errorMsg, e);
            String errorCode = determineErrorCode(e);
            throw new MOSIPAuthenticationException(errorMsg, errorCode, e);
        }
    }

    /**
     * Determine error code for retry handling
     *
     * @param e Exception that occurred
     * @return Appropriate error code for the exception
     */
    private String determineErrorCode(Exception e) {

        if (e instanceof MOSIPAuthenticationException &&
                ((MOSIPAuthenticationException) e).getErrorCode() != null) {
            return ((MOSIPAuthenticationException) e).getErrorCode();
        }

        if (e instanceof java.net.SocketTimeoutException) {
            return MOSIPErrorConstants.TIMEOUT_ERROR;
        }

        if (e instanceof java.net.ConnectException ||
                e instanceof java.net.UnknownHostException) {
            return MOSIPErrorConstants.NETWORK_ERROR;
        }

        return MOSIPErrorConstants.GENERAL_ERROR;
    }
}
