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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hc.core5.net.URIBuilder;
import org.wso2.carbon.identity.application.authenticator.mosip.client.RESTClient;
import org.wso2.carbon.identity.application.authenticator.mosip.constant.MOSIPAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.mosip.constant.MOSIPErrorConstants;
import org.wso2.carbon.identity.application.authenticator.mosip.dto.MOSIPKycAuthRequestDTO;
import org.wso2.carbon.identity.application.authenticator.mosip.dto.MOSIPKycAuthResponseDTO;
import org.wso2.carbon.identity.application.authenticator.mosip.dto.MOSIPKycExchangeRequestDTO;
import org.wso2.carbon.identity.application.authenticator.mosip.dto.MOSIPKycExchangeResponseDTO;
import org.wso2.carbon.identity.application.authenticator.mosip.dto.MOSIPSendOTPRequestDTO;
import org.wso2.carbon.identity.application.authenticator.mosip.dto.MOSIPSendOTPResponseDTO;
import org.wso2.carbon.identity.application.authenticator.mosip.exception.MOSIPAuthenticationException;
import org.wso2.carbon.identity.application.authenticator.mosip.util.CryptoUtil;
import org.wso2.carbon.identity.application.authenticator.mosip.util.KeyStoreManager;

import java.io.IOException;
import java.io.Serializable;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Service class that implements business logic for MOSIP Identity Authentication (IDA).
 * This class handles sending OTP, authenticating users with OTP, and retrieving KYC information
 * from the MOSIP Identity Authentication service.
 */
public class MOSIPAuthService implements Serializable {

    private static final long serialVersionUID = 9156072417087894671L;
    private static final Log log = LogFactory.getLog(MOSIPAuthService.class);
    private static final List<String> SUPPORTED_OTP_CHANNELS =
            Collections.unmodifiableList(Arrays.asList("email", "phone"));
    private static final int TRANSACTION_ID_MAX_LENGTH = 10;
    private static final String ALPHANUMERIC_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final Random RANDOM = new SecureRandom();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

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

    private final RESTClient RESTClient;

    /**
     * Default constructor that initializes a new MOSIPClient.
     */
    public MOSIPAuthService() {

        this.RESTClient = new RESTClient();
    }

    /**
     * Constructor with client dependency injection for testing.
     *
     * @param RESTClient The MOSIP client to use
     */
    public MOSIPAuthService(RESTClient RESTClient) {

        this.RESTClient = RESTClient;
    }

    /**
     * Generate a random alphanumeric transaction ID with maximum length of 10 characters.
     * Uses SecureRandom for better randomness in a production environment.
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
     * Build a fully qualified endpoint URL using Apache's URIBuilder.
     *
     * @param baseUrl      Base URL of the MOSIP service
     * @param endpointPath API endpoint path
     * @param pathSegments Additional path segments to append
     * @return Fully qualified URL as a string
     * @throws MOSIPAuthenticationException If URL building fails
     */
    private String buildEndpoint(String baseUrl, String endpointPath, String... pathSegments)
            throws MOSIPAuthenticationException {

        if (StringUtils.isEmpty(baseUrl) || StringUtils.isEmpty(endpointPath)) {
            throw new MOSIPAuthenticationException(
                    MOSIPErrorConstants.GENERAL_ERROR,
                    "Invalid URL parameters: baseUrl and endpointPath must not be empty"
            );
        }

        try {
            URIBuilder builder = new URIBuilder(baseUrl)
                    .setPath(endpointPath);

            if (pathSegments != null && pathSegments.length > 0) {
                builder.appendPathSegments(pathSegments);
            }

            return builder.build().toString();
        } catch (URISyntaxException e) {
            log.error("Error building endpoint URL", e);
            throw new MOSIPAuthenticationException(
                    MOSIPErrorConstants.GENERAL_ERROR,
                    "Invalid URL: " + e.getMessage(),
                    e
            );
        }
    }

    /**
     * Send OTP to the user's registered channels (email/phone).
     *
     * @param baseUrl       The base URL of the MOSIP IDA service
     * @param mispLK        MISP License Key
     * @param partnerId     Partner ID
     * @param oidcClientId  API Key
     * @param uin           User's UIN
     * @param channels      List of channels to send OTP (email/phone)
     * @param transactionId Transaction ID (optional, will generate if null)
     * @return MOSIPSendOtpResponseDTO with the response
     * @throws MOSIPAuthenticationException If sending OTP fails
     */
    public MOSIPSendOTPResponseDTO sendOtp(String baseUrl, String mispLK, String partnerId, String oidcClientId,
                                           String uin, List<String> channels, String transactionId) throws
            MOSIPAuthenticationException {

        // Input validation
        if (StringUtils.isEmpty(baseUrl) || StringUtils.isEmpty(mispLK) ||
                StringUtils.isEmpty(partnerId) || StringUtils.isEmpty(oidcClientId) ||
                StringUtils.isEmpty(uin)) {
            throw new MOSIPAuthenticationException(
                    MOSIPErrorConstants.INVALID_INPUT,
                    "Required parameters cannot be null or empty"
            );
        }

        if (channels == null || channels.isEmpty()) {
            throw new MOSIPAuthenticationException(
                    MOSIPErrorConstants.INVALID_INPUT,
                    "At least one OTP channel must be specified"
            );
        }

        if (log.isDebugEnabled()) {
            log.debug("Sending OTP with transaction ID: " + transactionId);
        }

        try {
            // Process transaction ID
            final String finalTransactionId;
            if (StringUtils.isEmpty(transactionId)) {
                finalTransactionId = generateTransactionId();
                if (log.isDebugEnabled()) {
                    log.debug("Generated new transaction ID: " + finalTransactionId);
                }
            } else if (transactionId.length() > TRANSACTION_ID_MAX_LENGTH) {
                finalTransactionId = transactionId.substring(0, TRANSACTION_ID_MAX_LENGTH);
                if (log.isDebugEnabled()) {
                    log.debug("Truncated transaction ID to: " + finalTransactionId);
                }
            } else {
                finalTransactionId = transactionId;
            }

            // Build request
            MOSIPSendOTPRequestDTO requestDTO = new MOSIPSendOTPRequestDTO();
            requestDTO.setId(MOSIPAuthenticatorConstants.DEFAULT_OTP_ID);
            requestDTO.setVersion(MOSIPAuthenticatorConstants.DEFAULT_AUTH_VERSION);
            requestDTO.setRequestTime(CryptoUtil.getUTCDateTime());
            requestDTO.setTransactionID(finalTransactionId);
            requestDTO.setIndividualId(uin);
            requestDTO.setIndividualIdType(MOSIPAuthenticatorConstants.DEFAULT_ID_TYPE);

            // Filter channels to include only supported ones
            List<String> supportedChannels = new ArrayList<>();
            for (String channel : channels) {
                if (SUPPORTED_OTP_CHANNELS.contains(channel)) {
                    supportedChannels.add(channel);
                }
            }

            if (supportedChannels.isEmpty()) {
                throw new MOSIPAuthenticationException(
                        MOSIPErrorConstants.INVALID_INPUT,
                        "No supported OTP channels specified. Supported channels: " + SUPPORTED_OTP_CHANNELS
                );
            }

            requestDTO.setOtpChannel(supportedChannels);

            // Build endpoint URL and prepare request
            String endpoint = buildEndpoint(
                    baseUrl,
                    MOSIPAuthenticatorConstants.SEND_OTP_ENDPOINT,
                    mispLK, partnerId, oidcClientId
                                           );

            String requestBody = OBJECT_MAPPER.writeValueAsString(requestDTO);
            String signature = CryptoUtil.generateMOSIPRequestSignatureAuthKey(requestBody);

            Map<String, String> headers = new HashMap<>();
            headers.put(MOSIPAuthenticatorConstants.SIGNATURE_HEADER, signature);
            headers.put(MOSIPAuthenticatorConstants.AUTHORIZATION_HEADER,
                    MOSIPAuthenticatorConstants.AUTHORIZATION_HEADER);

            Map<String, String> requestContext = new HashMap<>();
            requestContext.put(MOSIPAuthenticatorConstants.TRANSACTION_ID, finalTransactionId);

            // Send request and process response
            String responseBody = RESTClient.sendPostRequest(endpoint, requestBody, headers, requestContext);

            MOSIPSendOTPResponseDTO response = OBJECT_MAPPER.readValue(
                    responseBody, MOSIPSendOTPResponseDTO.class
                                                                      );

            if (response == null) {
                throw new MOSIPAuthenticationException(
                        MOSIPErrorConstants.RESPONSE_PARSING_ERROR,
                        "Received null response from MOSIP service"
                );
            }

            if (response.getErrors() != null && !response.getErrors().isEmpty()) {
                MOSIPSendOTPResponseDTO.ErrorData err = response.getErrors().get(0);
                throw new MOSIPAuthenticationException(err.getErrorCode(), err.getErrorMessage());
            }

            return response;
        } catch (MOSIPAuthenticationException e) {
            // Re-throw MOSIPAuthenticationException as is
            throw e;
        } catch (Exception e) {
            log.error("Error occurred while sending OTP: " + e.getMessage(), e);
            String errorCode = determineErrorCode(e);
            throw new MOSIPAuthenticationException(errorCode, "Error sending OTP: " + e.getMessage(), e);
        }
    }

    /**
     * Authenticate a user with MOSIP using UIN and OTP.
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
     */
    public MOSIPKycAuthResponseDTO authenticate(String baseUrl, String mispLK, String partnerId,
                                                String oidcClientId, String uin, String otp,
                                                String transactionId, String environment, String domainUri)
            throws MOSIPAuthenticationException {

        // Input validation
        if (StringUtils.isEmpty(baseUrl) || StringUtils.isEmpty(mispLK) ||
                StringUtils.isEmpty(partnerId) || StringUtils.isEmpty(oidcClientId) ||
                StringUtils.isEmpty(uin) || StringUtils.isEmpty(otp) ||
                StringUtils.isEmpty(transactionId)) {
            throw new MOSIPAuthenticationException(
                    MOSIPErrorConstants.INVALID_INPUT,
                    "Required parameters cannot be null or empty"
            );
        }

        if (log.isDebugEnabled()) {
            log.debug("Authenticating with transaction ID: " + transactionId);
        }

        try {
            // Build request
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

            MOSIPKycAuthRequestDTO.AuthRequest authReq = new MOSIPKycAuthRequestDTO.AuthRequest();
            authReq.setOtp(otp);
            authReq.setTimestamp(CryptoUtil.getUTCDateTime());

            String authReqStr = OBJECT_MAPPER.writeValueAsString(authReq);
            CryptoUtil.EncryptedRequestInfo encInfo = CryptoUtil.encryptRequest(authReqStr);

            requestDTO.setRequestHMAC(encInfo.getHmac());
            requestDTO.setRequestSessionKey(encInfo.getEncryptedSessionKey());
            requestDTO.setThumbprint(encInfo.getBase64UrlEncodedThumbprint());
            requestDTO.setRequest(encInfo.getBase64UrlEncodedRequest());

            // Build endpoint URL and prepare request
            String endpoint = buildEndpoint(
                    baseUrl,
                    MOSIPAuthenticatorConstants.KYC_AUTH_ENDPOINT,
                    mispLK, partnerId, oidcClientId
                                           );

            String requestBody = OBJECT_MAPPER.writeValueAsString(requestDTO);
            String signature = CryptoUtil.generateMOSIPRequestSignatureAuthKey(requestBody);

            Map<String, String> headers = new HashMap<>();
            headers.put(MOSIPAuthenticatorConstants.SIGNATURE_HEADER, signature);
            headers.put(MOSIPAuthenticatorConstants.AUTHORIZATION_HEADER,
                    MOSIPAuthenticatorConstants.AUTHORIZATION_HEADER);

            Map<String, String> requestContext = new HashMap<>();
            requestContext.put(MOSIPAuthenticatorConstants.TRANSACTION_ID, transactionId);

            // Send request and process response
            String respBody = RESTClient.sendPostRequest(endpoint, requestBody, headers, requestContext);
            MOSIPKycAuthResponseDTO resp = OBJECT_MAPPER.readValue(respBody, MOSIPKycAuthResponseDTO.class);

            if (resp == null) {
                throw new MOSIPAuthenticationException(
                        MOSIPErrorConstants.RESPONSE_PARSING_ERROR,
                        "Received null response from MOSIP service"
                );
            }

            if (resp.getErrors() != null && !resp.getErrors().isEmpty()) {
                MOSIPKycAuthResponseDTO.ErrorData err = resp.getErrors().get(0);
                throw new MOSIPAuthenticationException(err.getErrorCode(), err.getErrorMessage());
            }

            return resp;
        } catch (MOSIPAuthenticationException e) {
            // Re-throw MOSIPAuthenticationException as is
            throw e;
        } catch (IOException e) {
            log.error("I/O error during MOSIP authentication: " + e.getMessage(), e);
            throw new MOSIPAuthenticationException(
                    MOSIPErrorConstants.NETWORK_ERROR,
                    "Network error during authentication: " + e.getMessage(),
                    e);
        } catch (Exception e) {
            log.error("Error during MOSIP authentication: " + e.getMessage(), e);
            String errorCode = determineErrorCode(e);
            throw new MOSIPAuthenticationException(
                    errorCode,
                    "Authentication error: " + e.getMessage(),
                    e
            );
        }
    }

    /**
     * Exchange KYC token for user information.
     *
     * @param baseUrl         The base URL of the MOSIP IDA service
     * @param mispLK          MISP License Key
     * @param partnerId       Partner ID
     * @param oidcClientId    API Key
     * @param uin             User's UIN
     * @param kycToken        KYC token received from authentication
     * @param consentedClaims List of claims for which consent is given
     * @param transactionId   Transaction ID
     * @return MOSIPKycExchangeResponseDTO with the response
     * @throws MOSIPAuthenticationException If KYC exchange fails
     */
    public MOSIPKycExchangeResponseDTO kycExchange(String baseUrl, String mispLK, String partnerId,
                                                   String oidcClientId, String uin, String kycToken,
                                                   List<String> consentedClaims, String transactionId)
            throws MOSIPAuthenticationException {

        // Input validation
        if (StringUtils.isEmpty(baseUrl) || StringUtils.isEmpty(mispLK) ||
                StringUtils.isEmpty(partnerId) || StringUtils.isEmpty(oidcClientId) ||
                StringUtils.isEmpty(uin) || StringUtils.isEmpty(kycToken) ||
                StringUtils.isEmpty(transactionId)) {
            throw new MOSIPAuthenticationException(
                    MOSIPErrorConstants.INVALID_INPUT,
                    "Required parameters cannot be null or empty"
            );
        }

        if (consentedClaims == null || consentedClaims.isEmpty()) {
            throw new MOSIPAuthenticationException(
                    MOSIPErrorConstants.INVALID_INPUT,
                    "Consented claims list cannot be null or empty"
            );
        }

        if (log.isDebugEnabled()) {
            log.debug("Exchanging KYC token with transaction ID: " + transactionId);
        }

        try {
            // Build request
            MOSIPKycExchangeRequestDTO requestDTO = new MOSIPKycExchangeRequestDTO();
            requestDTO.setId(MOSIPAuthenticatorConstants.DEFAULT_KYC_EXCHANGE_ID);
            requestDTO.setVersion(MOSIPAuthenticatorConstants.DEFAULT_AUTH_VERSION);
            requestDTO.setRequestTime(CryptoUtil.getUTCDateTime());
            requestDTO.setTransactionID(transactionId);
            requestDTO.setIndividualId(uin);
            requestDTO.setKycToken(kycToken);
            requestDTO.setConsentObtained(consentedClaims);

            List<String> locales = new ArrayList<>();
            locales.add(MOSIPAuthenticatorConstants.DEFAULT_LOCALE);
            requestDTO.setLocales(locales);
            requestDTO.setRespType(MOSIPAuthenticatorConstants.RESP_TYPE);

            // Build endpoint URL and prepare request
            String endpoint = buildEndpoint(
                    baseUrl,
                    MOSIPAuthenticatorConstants.KYC_EXCHANGE_ENDPOINT,
                    mispLK, partnerId, oidcClientId
                                           );

            String requestBody = OBJECT_MAPPER.writeValueAsString(requestDTO);
            String signature = CryptoUtil.generateMOSIPRequestSignatureAuthKey(requestBody);

            Map<String, String> headers = new HashMap<>();
            headers.put(MOSIPAuthenticatorConstants.SIGNATURE_HEADER, signature);
            headers.put(MOSIPAuthenticatorConstants.AUTHORIZATION_HEADER,
                    MOSIPAuthenticatorConstants.AUTHORIZATION_HEADER);

            Map<String, String> requestContext = new HashMap<>();
            requestContext.put(MOSIPAuthenticatorConstants.TRANSACTION_ID, transactionId);

            // Send request and process response
            String respBody = RESTClient.sendPostRequest(endpoint, requestBody, headers, requestContext);
            MOSIPKycExchangeResponseDTO resp = OBJECT_MAPPER.readValue(respBody, MOSIPKycExchangeResponseDTO.class);

            if (resp == null) {
                throw new MOSIPAuthenticationException(
                        MOSIPErrorConstants.RESPONSE_PARSING_ERROR,
                        "Received null response from MOSIP service"
                );
            }

            if (resp.getErrors() != null && !resp.getErrors().isEmpty()) {
                MOSIPKycExchangeResponseDTO.ErrorData err = resp.getErrors().get(0);
                throw new MOSIPAuthenticationException(err.getErrorCode(), err.getErrorMessage());
            }

            return resp;
        } catch (MOSIPAuthenticationException e) {
            // Re-throw MOSIPAuthenticationException as is
            throw e;
        } catch (Exception e) {
            log.error("Error occurred during KYC exchange: " + e.getMessage(), e);
            String errorCode = determineErrorCode(e);
            throw new MOSIPAuthenticationException(
                    errorCode,
                    "Error during KYC exchange: " + e.getMessage(),
                    e
            );
        }
    }

    /**
     * Determine error code for retry handling based on exception type.
     *
     * @param e The exception to analyze
     * @return Appropriate error code
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

