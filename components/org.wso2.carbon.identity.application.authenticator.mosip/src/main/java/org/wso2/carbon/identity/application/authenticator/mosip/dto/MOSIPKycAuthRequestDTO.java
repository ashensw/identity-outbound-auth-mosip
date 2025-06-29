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

package org.wso2.carbon.identity.application.authenticator.mosip.dto;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

/**
 * Data Transfer Object for MOSIP KYC Authentication Request
 */
public class MOSIPKycAuthRequestDTO implements Serializable {

    private static final long serialVersionUID = 1L;

    private String id;
    private String version;
    private String individualId;
    private String individualIdType;
    private String transactionID;
    private String requestTime;
    private String specVersion;
    private String thumbprint;
    private String domainUri;
    private String env;
    private boolean consentObtained;
    private String request;
    private String requestHMAC;
    private String requestSessionKey;
    private Map<String, Object> metadata;
    private List<String> allowedKycAttributes;

    public String getId() {

        return id;
    }

    public void setId(String id) {

        this.id = id;
    }

    public String getVersion() {

        return version;
    }

    public void setVersion(String version) {

        this.version = version;
    }

    public String getIndividualId() {

        return individualId;
    }

    public void setIndividualId(String individualId) {

        this.individualId = individualId;
    }

    public String getIndividualIdType() {

        return individualIdType;
    }

    public void setIndividualIdType(String individualIdType) {

        this.individualIdType = individualIdType;
    }

    public String getTransactionID() {

        return transactionID;
    }

    public void setTransactionID(String transactionID) {

        this.transactionID = transactionID;
    }

    public String getRequestTime() {

        return requestTime;
    }

    public void setRequestTime(String requestTime) {

        this.requestTime = requestTime;
    }

    public String getSpecVersion() {

        return specVersion;
    }

    public void setSpecVersion(String specVersion) {

        this.specVersion = specVersion;
    }

    public String getThumbprint() {

        return thumbprint;
    }

    public void setThumbprint(String thumbprint) {

        this.thumbprint = thumbprint;
    }

    public String getDomainUri() {

        return domainUri;
    }

    public void setDomainUri(String domainUri) {

        this.domainUri = domainUri;
    }

    public String getEnv() {

        return env;
    }

    public void setEnv(String env) {

        this.env = env;
    }

    public boolean isConsentObtained() {

        return consentObtained;
    }

    public void setConsentObtained(boolean consentObtained) {

        this.consentObtained = consentObtained;
    }

    public String getRequest() {

        return request;
    }

    public void setRequest(String request) {

        this.request = request;
    }

    public String getRequestHMAC() {

        return requestHMAC;
    }

    public void setRequestHMAC(String requestHMAC) {

        this.requestHMAC = requestHMAC;
    }

    public String getRequestSessionKey() {

        return requestSessionKey;
    }

    public void setRequestSessionKey(String requestSessionKey) {

        this.requestSessionKey = requestSessionKey;
    }

    public Map<String, Object> getMetadata() {

        return metadata;
    }

    public void setMetadata(Map<String, Object> metadata) {

        this.metadata = metadata;
    }

    public List<String> getAllowedKycAttributes() {

        return allowedKycAttributes;
    }

    public void setAllowedKycAttributes(List<String> allowedKycAttributes) {

        this.allowedKycAttributes = allowedKycAttributes;
    }

    /**
     * Inner class for Auth Request details
     */
    public static class AuthRequest implements Serializable {

        private static final long serialVersionUID = 1L;

        private String otp;
        private String staticPin;
        private String timestamp;
        private List<Biometric> biometrics;
        private List<KeyBindedToken> keyBindedTokens;
        private String password;

        public String getOtp() {

            return otp;
        }

        public void setOtp(String otp) {

            this.otp = otp;
        }

        public String getStaticPin() {

            return staticPin;
        }

        public void setStaticPin(String staticPin) {

            this.staticPin = staticPin;
        }

        public String getTimestamp() {

            return timestamp;
        }

        public void setTimestamp(String timestamp) {

            this.timestamp = timestamp;
        }

        public List<Biometric> getBiometrics() {

            return biometrics;
        }

        public void setBiometrics(List<Biometric> biometrics) {

            this.biometrics = biometrics;
        }

        public List<KeyBindedToken> getKeyBindedTokens() {

            return keyBindedTokens;
        }

        public void setKeyBindedTokens(List<KeyBindedToken> keyBindedTokens) {

            this.keyBindedTokens = keyBindedTokens;
        }

        public String getPassword() {

            return password;
        }

        public void setPassword(String password) {

            this.password = password;
        }
    }

    /**
     * Inner class for Biometric details
     */
    public static class Biometric implements Serializable {

        private static final long serialVersionUID = 1L;

        private String data;
        private String hash;
        private String sessionKey;
        private String specVersion;
        private String thumbprint;

        public String getData() {

            return data;
        }

        public void setData(String data) {

            this.data = data;
        }

        public String getHash() {

            return hash;
        }

        public void setHash(String hash) {

            this.hash = hash;
        }

        public String getSessionKey() {

            return sessionKey;
        }

        public void setSessionKey(String sessionKey) {

            this.sessionKey = sessionKey;
        }

        public String getSpecVersion() {

            return specVersion;
        }

        public void setSpecVersion(String specVersion) {

            this.specVersion = specVersion;
        }

        public String getThumbprint() {

            return thumbprint;
        }

        public void setThumbprint(String thumbprint) {

            this.thumbprint = thumbprint;
        }
    }

    /**
     * Inner class for KeyBindedToken details
     */
    public static class KeyBindedToken implements Serializable {

        private static final long serialVersionUID = 1L;

        // Add properties as needed based on the actual implementation

        // Default constructor
        public KeyBindedToken() {

        }
    }
}
