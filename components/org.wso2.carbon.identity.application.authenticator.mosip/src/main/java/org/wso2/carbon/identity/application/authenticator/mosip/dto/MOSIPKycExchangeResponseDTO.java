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
import java.util.Map;
import java.util.List;

/**
 * Data Transfer Object for MOSIP KYC Exchange Response
 */
public class MOSIPKycExchangeResponseDTO implements Serializable {

    private static final long serialVersionUID = 1L;

    private String id;
    private String version;
    private String responseTime;
    private String transactionID;
    private ResponseData response;
    private List<ErrorData> errors;

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

    public String getResponseTime() {

        return responseTime;
    }

    public void setResponseTime(String responseTime) {

        this.responseTime = responseTime;
    }

    public String getTransactionID() {

        return transactionID;
    }

    public void setTransactionID(String transactionID) {

        this.transactionID = transactionID;
    }

    public ResponseData getResponse() {

        return response;
    }

    public void setResponse(ResponseData response) {

        this.response = response;
    }

    public List<ErrorData> getErrors() {

        return errors;
    }

    public void setErrors(List<ErrorData> errors) {

        this.errors = errors;
    }

    public static class ResponseData implements Serializable {

        private String encryptedKyc;
        private String idType;
        private String kycStatus;
        private Map<String, Object> identity;

        public String getEncryptedKyc() {

            return encryptedKyc;
        }

        public void setEncryptedKyc(String encryptedKyc) {

            this.encryptedKyc = encryptedKyc;
        }

        public String getIdType() {

            return idType;
        }

        public void setIdType(String idType) {

            this.idType = idType;
        }

        public String getKycStatus() {

            return kycStatus;
        }

        public void setKycStatus(String kycStatus) {

            this.kycStatus = kycStatus;
        }

        public Map<String, Object> getIdentity() {

            return identity;
        }

        public void setIdentity(Map<String, Object> identity) {

            this.identity = identity;
        }
    }

    public static class ErrorData implements Serializable {

        private String errorCode;
        private String errorMessage;

        public String getErrorCode() {

            return errorCode;
        }

        public void setErrorCode(String errorCode) {

            this.errorCode = errorCode;
        }

        public String getErrorMessage() {

            return errorMessage;
        }

        public void setErrorMessage(String errorMessage) {

            this.errorMessage = errorMessage;
        }
    }
}
