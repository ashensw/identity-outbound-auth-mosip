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

package org.wso2.carbon.identity.application.authenticator.mosip.constant;

/**
 * Constants for error codes used in the MOSIP authenticator
 */
public class MOSIPErrorConstants {

    // General error codes
    public static final String GENERAL_ERROR = "MOSIP_ERROR";

    // Communication error codes
    public static final String COMMUNICATION_ERROR = "MOSIP_COMM_ERROR";
    public static final String NETWORK_ERROR = "MOSIP_NETWORK_ERROR";
    public static final String TIMEOUT_ERROR = "MOSIP_TIMEOUT_ERROR";
    public static final String INVALID_INPUT = "MOSIP_INVALID_INPUT";
    public static final String RESPONSE_PARSING_ERROR = "MOSIP_RESPONSE_PARSING_ERROR";

    // Authentication error codes
    public static final String AUTH_ERROR = "MOSIP_AUTH_ERROR";
    public static final String OTP_ERROR = "MOSIP_OTP_ERROR";
    public static final String OTP_INVALID = "MOSIP_OTP_INVALID";
    public static final String OTP_EXPIRED = "MOSIP_OTP_EXPIRED";
    public static final String KYC_ERROR = "MOSIP_KYC_ERROR";

    // HTTP error codes
    public static final String HTTP_500 = "MOSIP_HTTP_500";
    public static final String HTTP_503 = "MOSIP_HTTP_503";

    // Configuration error codes
    public static final String CONFIG_ERROR = "MOSIP_CONFIG_ERROR";
    public static final String MISSING_PARAMETER = "MOSIP_MISSING_PARAM";
    public static final String INVALID_PARAMETER = "MOSIP_INVALID_PARAM";

    // User friendly error messages
    public static final String USER_FRIENDLY_OTP_ERROR =
            "The OTP you entered is incorrect or has expired. Please try again.";
    public static final String USER_FRIENDLY_NETWORK_ERROR =
            "Unable to connect to MOSIP services. Please try again later.";
    public static final String USER_FRIENDLY_CONFIG_ERROR =
            "MOSIP authenticator is not configured properly. Please contact your system administrator.";
    public static final String USER_FRIENDLY_GENERAL_ERROR =
            "An error occurred during authentication. Please try again.";
}
