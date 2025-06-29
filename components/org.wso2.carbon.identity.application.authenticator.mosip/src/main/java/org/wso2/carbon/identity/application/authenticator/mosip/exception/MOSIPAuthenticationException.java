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

package org.wso2.carbon.identity.application.authenticator.mosip.exception;

/**
 * Base exception class for MOSIP authentication failures
 */
public class MOSIPAuthenticationException extends Exception {

    private static final long serialVersionUID = -8979421104372963012L;

    private String errorCode;

    /**
     * Constructor with error message
     *
     * @param message Error message
     */
    public MOSIPAuthenticationException(String message) {

        super(message);
    }

    /**
     * Constructor with error message and cause
     *
     * @param message Error message
     * @param cause   Cause of the exception
     */
    public MOSIPAuthenticationException(String message, Throwable cause) {

        super(message, cause);
    }

    /**
     * Constructor with error code and message
     *
     * @param errorCode Error code
     * @param message   Error message
     */
    public MOSIPAuthenticationException(String errorCode, String message) {

        super(message);
        this.errorCode = errorCode;
    }

    /**
     * Constructor with error code, message, and cause
     *
     * @param errorCode Error code
     * @param message   Error message
     * @param cause     Cause of the exception
     */
    public MOSIPAuthenticationException(String errorCode, String message, Throwable cause) {

        super(message, cause);
        this.errorCode = errorCode;
    }

    /**
     * Get the error code
     *
     * @return Error code
     */
    public String getErrorCode() {

        return errorCode;
    }
}