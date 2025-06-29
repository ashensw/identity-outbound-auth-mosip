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
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicHttpResponse;
import org.apache.hc.core5.util.Timeout;
import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authenticator.mosip.constant.MOSIPAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.mosip.constant.MOSIPErrorConstants;
import org.wso2.carbon.identity.application.authenticator.mosip.exception.MOSIPAuthenticationException;

import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Client class responsible for handling HTTP communication with MOSIP APIs.
 */
public class MOSIPClient implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Log log = LogFactory.getLog(MOSIPClient.class);

    // HTTP success range constants
    private static final int HTTP_SUCCESS_START = HttpStatus.SC_OK;
    private static final int HTTP_SUCCESS_END = 299;

    // Default timeout values in milliseconds
    private static final Timeout DEFAULT_CONNECT_TIMEOUT = Timeout.ofMilliseconds(10000);
    private static final Timeout DEFAULT_CONNECTION_REQUEST_TIMEOUT = Timeout.ofMilliseconds(10000);
    private static final Timeout DEFAULT_SOCKET_TIMEOUT = Timeout.ofMilliseconds(30000);

    // Connection pool settings
    private static final int DEFAULT_MAX_TOTAL_CONNECTIONS = 100;
    private static final int DEFAULT_MAX_CONNECTIONS_PER_ROUTE = 50;
    private static final int CONNECTION_IDLE_TIMEOUT_SECONDS = 60;
    private static final int CONNECTION_MONITOR_INTERVAL_MS = 30000;

    // Shared connection manager for all instances
    private static volatile PoolingHttpClientConnectionManager connectionManager;

    // Shared request configuration
    private static volatile RequestConfig requestConfig;

    // Shared HTTP client for better resource utilization
    private static volatile CloseableHttpClient sharedHttpClient;

    // Shared monitor thread
    private static volatile Thread connectionMonitorThread;

    // Instance HTTP client
    private transient final CloseableHttpClient httpClient;

    /**
     * Initialize shared resources for all MOSIPClient instances
     */
    static {
        initConnectionManager();
        initRequestConfig();
        initSharedHttpClient();
    }

    /**
     * Initialize the connection manager with pooling settings
     */
    private static synchronized void initConnectionManager() {

        if (connectionManager == null) {
            connectionManager = new PoolingHttpClientConnectionManager();
            connectionManager.setMaxTotal(DEFAULT_MAX_TOTAL_CONNECTIONS);
            connectionManager.setDefaultMaxPerRoute(DEFAULT_MAX_CONNECTIONS_PER_ROUTE);
            startConnectionMonitorThread();
        }
    }

    /**
     * Initialize the shared request configuration
     */
    private static synchronized void initRequestConfig() {

        if (requestConfig == null) {
            requestConfig = RequestConfig.custom()
                    .setConnectTimeout(DEFAULT_CONNECT_TIMEOUT)
                    .setConnectionRequestTimeout(DEFAULT_CONNECTION_REQUEST_TIMEOUT)
                    .setResponseTimeout(DEFAULT_SOCKET_TIMEOUT)
                    .build();
        }
    }

    /**
     * Initialize the shared HTTP client
     */
    private static synchronized void initSharedHttpClient() {

        if (sharedHttpClient == null) {
            sharedHttpClient = HttpClients.custom()
                    .setDefaultRequestConfig(requestConfig)
                    .setConnectionManager(connectionManager)
                    .build();
        }
    }

    /**
     * Start a background thread to periodically clean up idle and expired connections
     */
    private static synchronized void startConnectionMonitorThread() {

        if (connectionMonitorThread == null || !connectionMonitorThread.isAlive()) {
            connectionMonitorThread = new Thread(() -> {
                try {
                    while (!Thread.currentThread().isInterrupted()) {
                        synchronized (MOSIPClient.class) {
                            connectionManager.closeExpired();
                            connectionManager.closeIdle(Timeout.ofSeconds(CONNECTION_IDLE_TIMEOUT_SECONDS));
                        }
                        Thread.sleep(CONNECTION_MONITOR_INTERVAL_MS);
                    }
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                }
            });
            connectionMonitorThread.setDaemon(true);
            connectionMonitorThread.setName("mosip-connection-monitor");
            connectionMonitorThread.start();
        }
    }

    /**
     * Default constructor that uses the shared HTTP client for better resource utilization
     */
    public MOSIPClient() {

        this.httpClient = sharedHttpClient;
    }

    /**
     * Sends a POST request to the specified URL with the given payload and headers.
     *
     * @param url            The endpoint URL
     * @param requestBody    The request body as JSON string
     * @param headers        The HTTP headers to include
     * @param requestContext Additional context information for logging
     * @return Response body as string
     * @throws MOSIPAuthenticationException If an error occurs during the API call
     */
    public String sendPostRequest(String url, String requestBody, Map<String, String> headers,
                                  Map<String, String> requestContext)
            throws MOSIPAuthenticationException {

        String transactionId = requestContext.getOrDefault(MOSIPAuthenticatorConstants.TRANSACTION_ID, "unknown");

        if (log.isDebugEnabled()) {
            log.debug(String.format("[Transaction ID: %s] Sending POST request to MOSIP API: %s",
                    transactionId, url));
        }

        HttpPost httpPost;

        try {
            httpPost = new HttpPost(url);

            // Set headers
            for (Map.Entry<String, String> header : headers.entrySet()) {
                httpPost.setHeader(header.getKey(), header.getValue());
            }
            httpPost.setHeader(MOSIPAuthenticatorConstants.CONTENT_TYPE, MOSIPAuthenticatorConstants.APPLICATION_JSON);

            // Set request body
            StringEntity entity = new StringEntity(requestBody, StandardCharsets.UTF_8);
            httpPost.setEntity(entity);
            // Log request body at INFO level
            if (log.isInfoEnabled()) {
                log.info(String.format("[Transaction ID: %s] Request Body: %s", transactionId, requestBody));
            }
            // Execute request
            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                int statusCode = response.getCode();
                String reasonPhrase = response.getReasonPhrase();
                if (reasonPhrase == null) {
                    reasonPhrase = new BasicHttpResponse(statusCode).getReasonPhrase();
                }

                String responseBody;
                try {
                    responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
                } catch (org.apache.hc.core5.http.ParseException e) {
                    throw new MOSIPAuthenticationException(MOSIPErrorConstants.COMMUNICATION_ERROR,
                            "Error parsing response from MOSIP API", e);
                }
                // Log response body at INFO level
                if (log.isInfoEnabled()) {
                    log.info(String.format("[Transaction ID: %s] Response Body: %s", transactionId, responseBody));
                }

                if (statusCode >= HTTP_SUCCESS_START && statusCode <= HTTP_SUCCESS_END) {
                    if (log.isDebugEnabled()) {
                        log.debug(String.format("[Transaction ID: %s] Successful response from MOSIP API (Status: %d)",
                                transactionId, statusCode));
                    }
                    checkResponseForErrors(responseBody, transactionId);
                    return responseBody;
                } else {
                    String errorMsg = String.format("MOSIP API call failed with status code: %d, transaction ID: %s",
                            statusCode, transactionId);
                    log.error(errorMsg + ", Response: " + sanitizeLogMessage(responseBody));

                    // Try to extract detailed error information from the response body first
                    try {
                        checkResponseForErrors(responseBody, transactionId);
                    } catch (MOSIPAuthenticationException e) {
                        // If we found specific error details in the response body, use those
                        throw new MOSIPAuthenticationException(
                                e.getErrorCode(),
                                String.format("HTTP %d: %s - %s", statusCode, reasonPhrase, e.getMessage()),
                                e.getCause()
                        );
                    }

                    // If no specific error was found in the body, use a generic error based on HTTP status
                    throw new MOSIPAuthenticationException(
                            MOSIPErrorConstants.COMMUNICATION_ERROR,
                            String.format("MOSIP API returned HTTP %d: %s", statusCode, reasonPhrase)
                    );
                }
            }
        } catch (IOException e) {
            String errorMsg = String.format("I/O error during MOSIP API call: %s, transaction ID: %s",
                    e.getMessage(), transactionId);
            log.error(errorMsg, e);

            throw new MOSIPAuthenticationException(
                    MOSIPErrorConstants.NETWORK_ERROR,
                    "Network error communicating with MOSIP services: " + e.getMessage(),
                    e
            );
        }
    }

    /**
     * Check response body for MOSIP API errors
     *
     * @param responseBody  The response body as string
     * @param transactionId The transaction ID for logging
     * @throws MOSIPAuthenticationException If errors are found in the response
     */
    private void checkResponseForErrors(String responseBody, String transactionId)
            throws MOSIPAuthenticationException {

        if (responseBody == null || responseBody.isEmpty()) {
            return;
        }

        try {
            JSONObject responseJson = new JSONObject(responseBody);

            if (responseJson.has(MOSIPAuthenticatorConstants.ERRORS)) {
                JSONArray errorsArray = responseJson.getJSONArray(MOSIPAuthenticatorConstants.ERRORS);
                if (!errorsArray.isEmpty()) {
                    JSONObject errorObj = errorsArray.getJSONObject(0);
                    String errorCode = errorObj.optString(MOSIPAuthenticatorConstants.ERROR_CODE, "UNKNOWN_ERROR");
                    String errorMessage =
                            errorObj.optString(MOSIPAuthenticatorConstants.ERROR_MESSAGE, "Unknown error occurred");

                    log.error(String.format("[Transaction ID: %s] MOSIP API error: %s - %s",
                            transactionId, errorCode, errorMessage));

                    throw new MOSIPAuthenticationException(errorCode, errorMessage);
                }
            }
        } catch (org.json.JSONException e) {
            // Ignore if response is not valid JSON
        }
    }

    /**
     * Sanitize message for logging to prevent log injection attacks
     *
     * @param message The message to sanitize
     * @return The sanitized message
     */
    private String sanitizeLogMessage(String message) {

        if (message == null) {
            return "";
        }
        return message.replace('\n', ' ').replace('\r', ' ');
    }
}
