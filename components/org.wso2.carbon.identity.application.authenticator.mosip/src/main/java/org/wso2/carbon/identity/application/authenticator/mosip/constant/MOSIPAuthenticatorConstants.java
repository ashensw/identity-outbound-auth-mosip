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
 * Constants used in the MOSIP Authenticator implementation
 */
public class MOSIPAuthenticatorConstants {

    // Authentication parameters
    public static final String UIN = "uin";
    public static final String UIN_PARAM = "mosip_uin";
    public static final String OTP = "OTPCode";
    public static final String TRANSACTION_ID = "transactionID";
    public static final String SESSION_DATA_KEY = "sessionDataKey";
    public static final String RETRY_PARAM = "&authFailure=true&authFailureMsg=authentication.failed";
    public static final String RESEND = "resend";
    public static final String RESEND_PARAM = "&resend=true";
    public static final String MULTI_OPTION_URI_PARAM = "&multiOptionURI=";

    // OTP channels
    public static final String[] OTP_CHANNELS = {"email", "phone"};

    // Configuration parameters
    public static final String BASE_URL = "baseUrl";
    public static final String MISP_LICENSE_KEY = "mispLicenseKey";
    public static final String PARTNER_ID = "partnerId";
    public static final String OIDC_CLIENT_ID = "oidcClientId";
    public static final String DOMAIN_URI = "domainUri";
    public static final String ENV = "env";
    public static final String DEFAULT_ENVIRONMENT = "Staging";
    public static final String RESP_TYPE = "JWT";
    public static final String DEFAULT_LOCALE = "en";

    // KeyStore configuration parameters
    public static final String AUTH_KEYSTORE_FILE = "authKeystoreFile";
    public static final String AUTH_KEYSTORE_ALIAS = "authKeystoreAlias";
    public static final String AUTH_PEM_FILE = "authPemFile";
    public static final String IDA_CERT_FILE = "idaCertFile";
    public static final String KEYSTORE_PASSWORD = "keystorePassword";
    public static final String DEFAULT_AUTH_KEYSTORE_FILE = "mosip_auth.p12";
    public static final String DEFAULT_AUTH_KEYSTORE_ALIAS = "mosip-auth";
    public static final String DEFAULT_AUTH_PEM_FILE = "mpartner-default-wso2-auth.pem";
    public static final String DEFAULT_IDA_CERT_FILE = "ida-partner.cer";

    // API endpoints
    public static final String SEND_OTP_ENDPOINT = "/idauthentication/v1/otp";
    public static final String KYC_AUTH_ENDPOINT = "/idauthentication/v1/kyc-auth/delegated";
    public static final String KYC_EXCHANGE_ENDPOINT = "/idauthentication/v1/kyc-exchange/delegated";

    // JSP page paths
    public static final String MOSIP_LOGIN_PAGE = "authenticationendpoint/mosip_login.jsp";
    public static final String MOSIP_OTP_PAGE = "authenticationendpoint/mosip_otp.jsp";

    // HTTP Headers
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String SIGNATURE_HEADER = "signature";
    public static final String CONTENT_TYPE = "Content-Type";
    public static final String APPLICATION_JSON = "application/json";

    // Error handling constants
    public static final String ERRORS = "errors";
    public static final String ERRORS_ARRAY = "errors";
    public static final String ERROR_CODE = "errorCode";
    public static final String ERROR_MESSAGE = "errorMessage";

    // Default values and identifiers
    public static final String DEFAULT_OTP_ID = "mosip.identity.otp";
    public static final String DEFAULT_KYC_AUTH_ID = "mosip.identity.kycauth";
    public static final String DEFAULT_KYC_EXCHANGE_ID = "mosip.identity.kycexchange";
    public static final String DEFAULT_AUTH_VERSION = "1.0";
    public static final String DEFAULT_ID_TYPE = "UIN";

    // Authenticator metadata
    public static final String AUTHENTICATOR_NAME = "MOSIPAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "MOSIP";

    // Parameter names for multi-option
    public static final String MULTI_OPTION_URI = "multiOptionURI";
}
