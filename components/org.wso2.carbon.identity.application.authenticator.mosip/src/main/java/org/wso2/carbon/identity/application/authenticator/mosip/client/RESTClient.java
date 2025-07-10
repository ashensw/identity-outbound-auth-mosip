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

package org.wso2.carbon.identity.application.authenticator.mosip.client;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.util.Timeout;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authenticator.mosip.constant.MOSIPAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.mosip.constant.MOSIPErrorConstants;
import org.wso2.carbon.identity.application.authenticator.mosip.exception.MOSIPAuthenticationException;

import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Client for sending HTTP POST requests to MOSIP services.
 * This implementation follows WSO2 patterns with appropriate connection pooling and error handling.
 */
public class RESTClient implements Serializable {

    private static final long serialVersionUID = -6167112874566318017L;
    private static final Log log = LogFactory.getLog(RESTClient.class);

    // Timeout configuration
    private static final Timeout CONNECT_TIMEOUT = Timeout.ofMilliseconds(10_000);
    private static final Timeout RESPONSE_TIMEOUT = Timeout.ofMilliseconds(30_000);
    private static final Timeout CONNECTION_REQUEST_TIMEOUT = Timeout.ofMilliseconds(10_000);

    // Connection pool configuration
    private static final int MAX_TOTAL_CONNECTIONS = 50;
    private static final int MAX_CONNECTIONS_PER_ROUTE = 20;

    private final transient CloseableHttpClient httpClient;

    /**
     * Constructs a RESTClient with default configuration.
     */
    public RESTClient() {

        // Set up connection pooling
        PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager();
        connectionManager.setMaxTotal(MAX_TOTAL_CONNECTIONS);
        connectionManager.setDefaultMaxPerRoute(MAX_CONNECTIONS_PER_ROUTE);

        ConnectionConfig connectionConfig = ConnectionConfig.custom()
                .setConnectTimeout(CONNECT_TIMEOUT)
                .build();
        connectionManager.setDefaultConnectionConfig(connectionConfig);

        // Configure request defaults
        RequestConfig requestConfig = RequestConfig.custom()
                .setResponseTimeout(RESPONSE_TIMEOUT)
                .setConnectionRequestTimeout(CONNECTION_REQUEST_TIMEOUT)
                .build();

        // Build the HTTP client
        this.httpClient = HttpClients.custom()
                .setConnectionManager(connectionManager)
                .setDefaultRequestConfig(requestConfig)
                .build();
    }

    /**
     * Constructor for testing purposes, allowing injection of a mock client.
     *
     * @param httpClient The custom HttpClient to use
     */
    public RESTClient(CloseableHttpClient httpClient) {

        this.httpClient = httpClient;
    }

    /**
     * Sends an HTTP POST request with a JSON body to the specified URL.
     *
     * @param url      The target endpoint URL
     * @param jsonBody The JSON payload as a String
     * @param headers  A map of HTTP headers to include in the request
     * @param context  A map containing contextual information
     * @return The response body as a String if the request is successful
     * @throws MOSIPAuthenticationException if the request fails
     */
    public String sendPostRequest(String url, String jsonBody, Map<String, String> headers, Map<String, String> context)
            throws MOSIPAuthenticationException {

        final String transactionId = context != null
                ? context.getOrDefault(MOSIPAuthenticatorConstants.TRANSACTION_ID, "unknown-transaction")
                : "unknown-transaction";

        if (log.isDebugEnabled()) {
            log.debug(String.format("[TX_ID: %s] Preparing POST request to URL: %s", transactionId, url));
            log.debug(String.format("[TX_ID: %s] Request Body: %s", transactionId, jsonBody));
        }

        HttpPost postRequest = new HttpPost(url);
        postRequest.setEntity(new StringEntity(jsonBody, StandardCharsets.UTF_8));
        postRequest.setHeader(MOSIPAuthenticatorConstants.CONTENT_TYPE, MOSIPAuthenticatorConstants.APPLICATION_JSON);
        if (headers != null) {
            headers.forEach(postRequest::setHeader);
        }

        try {
            // Using HttpClientResponseHandler simplifies resource management.
            // The lambda handles the response, and any checked exceptions that are not
            return httpClient.execute(postRequest, response -> {
                try {
                    final int statusCode = response.getCode();
                    final String responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

                    if (log.isDebugEnabled()) {
                        log.debug(String.format("[TX_ID: %s] Response Status: %d", transactionId, statusCode));
                        log.debug(
                                String.format("[TX_ID: %s] Response Body: %s", transactionId, responseBody));
                    }

                    // Check for MOSIP-specific errors in the response body first.
                    validateMOSIPResponseForErrors(responseBody, transactionId);

                    // Now, check if the HTTP status code indicates success.
                    if (statusCode >= HttpStatus.SC_OK && statusCode < HttpStatus.SC_REDIRECTION) { // 2xx range
                        return responseBody;
                    } else {
                        String reasonPhrase = response.getReasonPhrase();
                        log.error(String.format("[TX_ID: %s] Received unsuccessful HTTP status: %d %s",
                                transactionId, statusCode, reasonPhrase));
                        throw new MOSIPAuthenticationException(MOSIPErrorConstants.COMMUNICATION_ERROR,
                                String.format("HTTP Error: %d %s", statusCode, reasonPhrase));
                    }
                } catch (ParseException | MOSIPAuthenticationException e) {
                    // Wrap checked exceptions in an IOException to allow them to be thrown from the lambda.
                    throw new IOException(e);
                }
            });
        } catch (IOException e) {
            // Unwrap the exception to see if it was one of ours.
            if (e.getCause() instanceof MOSIPAuthenticationException) {
                throw (MOSIPAuthenticationException) e.getCause();
            }
            if (e.getCause() instanceof ParseException) {
                log.error(String.format("[TX_ID: %s] Failed to parse HTTP response from %s: %s",
                        transactionId, url, e.getMessage()), e);
                throw new MOSIPAuthenticationException(MOSIPErrorConstants.COMMUNICATION_ERROR,
                        "Failed to parse response from MOSIP service.", e);
            }
            // Catches genuine I/O errors (e.g., network issues, timeouts).
            log.error(String.format("[TX_ID: %s] I/O error during POST request to %s: %s",
                    transactionId, url, e.getMessage()), e);
            throw new MOSIPAuthenticationException(MOSIPErrorConstants.NETWORK_ERROR,
                    "Network error communicating with MOSIP service: " + e.getMessage(), e);
        }
    }

    /**
     * Validates MOSIP response for standard error structure.
     *
     * @param responseBody  The JSON response from the MOSIP API
     * @param transactionId The transaction ID for logging context
     * @throws MOSIPAuthenticationException if the response contains a MOSIP error
     */
    private void validateMOSIPResponseForErrors(String responseBody, String transactionId)
            throws MOSIPAuthenticationException {

        if (responseBody == null || responseBody.trim().isEmpty()) {
            return;
        }

        try {
            JSONObject responseObject = new JSONObject(responseBody);
            if (responseObject.has(MOSIPAuthenticatorConstants.ERRORS)) {
                JSONArray errors = responseObject.optJSONArray(MOSIPAuthenticatorConstants.ERRORS);
                if (errors != null && !errors.isEmpty()) {
                    JSONObject error = errors.getJSONObject(0);
                    String errorCode = error.optString(MOSIPAuthenticatorConstants.ERROR_CODE, "UNKNOWN_API_ERROR");
                    String errorMessage = error.optString(MOSIPAuthenticatorConstants.ERROR_MESSAGE,
                            "No error message provided");

                    log.error(String.format("[TX_ID: %s] MOSIP API error. Code: %s, Message: %s",
                            transactionId, errorCode, errorMessage));
                    throw new MOSIPAuthenticationException(errorCode, errorMessage);
                }
            }
        } catch (JSONException e) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("[TX_ID: %s] Could not parse response as JSON: %s",
                        transactionId, e.getMessage()));
            }
        }
    }
}