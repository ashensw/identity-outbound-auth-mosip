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
 * Data Transfer Object for MOSIP Send OTP Request (aligned with MOSIP plugin IdaSendOtpRequest)
 */
public class MOSIPSendOtpRequestDTO implements Serializable {

    private static final long serialVersionUID = 1L;

    private String id;
    private String version;
    private String individualId;
    private String individualIdType;
    private String transactionID;
    private String requestTime;
    private List<String> otpChannel;

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

    public List<String> getOtpChannel() {

        return otpChannel;
    }

    public void setOtpChannel(List<String> otpChannel) {

        this.otpChannel = otpChannel;
    }
}


