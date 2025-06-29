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

/**
 * Data Transfer Object for MOSIP KYC Exchange Request
 */
public class MOSIPKycExchangeRequestDTO implements Serializable {

    private static final long serialVersionUID = 1L;

    private String id;
    private String version;
    private String requestTime;
    private String transactionID;
    private String individualId;
    private String kycToken;
    private List<String> consentObtained;
    private List<String> locales;
    private String respType;

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

    public String getRequestTime() {

        return requestTime;
    }

    public void setRequestTime(String requestTime) {

        this.requestTime = requestTime;
    }

    public String getTransactionID() {

        return transactionID;
    }

    public void setTransactionID(String transactionID) {

        this.transactionID = transactionID;
    }

    public String getIndividualId() {

        return individualId;
    }

    public void setIndividualId(String individualId) {

        this.individualId = individualId;
    }

    public String getKycToken() {

        return kycToken;
    }

    public void setKycToken(String kycToken) {

        this.kycToken = kycToken;
    }

    public List<String> getConsentObtained() {

        return consentObtained;
    }

    public void setConsentObtained(List<String> consentObtained) {

        this.consentObtained = consentObtained;
    }

    public List<String> getLocales() {

        return locales;
    }

    public void setLocales(List<String> locales) {

        this.locales = locales;
    }

    public String getRespType() {

        return respType;
    }

    public void setRespType(String respType) {

        this.respType = respType;
    }
}
