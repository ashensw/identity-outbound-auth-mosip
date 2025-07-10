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

package org.wso2.carbon.identity.application.authenticator.mosip.internal;

import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.mosip.client.RESTClient;
import org.wso2.carbon.identity.application.authenticator.mosip.service.MOSIPAuthService;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.ArrayList;
import java.util.List;

/**
 * Service data holder for MOSIP Authenticator.
 * This class holds references to OSGi services and components used by the MOSIP authenticator.
 */
public class MOSIPAuthenticatorServiceDataHolder {

    private static final MOSIPAuthenticatorServiceDataHolder instance = new MOSIPAuthenticatorServiceDataHolder();

    private List<ApplicationAuthenticator> authenticators = new ArrayList<>();
    private RealmService realmService;

    // Core service instances with lazy initialization
    private RESTClient RESTClient = null;
    private MOSIPAuthService mosipAuthService = null;

    private MOSIPAuthenticatorServiceDataHolder() {
        // Empty constructor - services will be initialized lazily
    }

    public static MOSIPAuthenticatorServiceDataHolder getInstance() {

        return instance;
    }

    /**
     * Add an authenticator to the list of authenticators
     *
     * @param authenticator The authenticator to add
     */
    public void addAuthenticator(ApplicationAuthenticator authenticator) {

        authenticators.add(authenticator);
    }

    /**
     * Remove an authenticator from the list of authenticators
     *
     * @param authenticator The authenticator to remove
     */
    public void removeAuthenticator(ApplicationAuthenticator authenticator) {

        authenticators.remove(authenticator);
    }

    /**
     * Get the list of authenticators
     *
     * @return The list of authenticators
     */
    public List<ApplicationAuthenticator> getAuthenticators() {

        return authenticators;
    }

    /**
     * Get the realm service
     *
     * @return The realm service
     */
    public RealmService getRealmService() {

        return realmService;
    }

    /**
     * Set the realm service
     *
     * @param realmService The realm service
     */
    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    /**
     * Get the MOSIP client with lazy initialization
     *
     * @return The MOSIP client
     */
    public RESTClient getMOSIPClient() {

        if (RESTClient == null) {
            RESTClient = new RESTClient();
        }
        return RESTClient;
    }

    /**
     * Set the REST client
     *
     * @param RESTClient The MOSIP client
     */
    public void setRESTClient(RESTClient RESTClient) {

        this.RESTClient = RESTClient;
    }

    /**
     * Get the MOSIP auth service with lazy initialization
     *
     * @return The MOSIP auth service
     */
    public MOSIPAuthService getMOSIPAuthService() {

        if (mosipAuthService == null) {
            mosipAuthService = new MOSIPAuthService(getMOSIPClient());
        }
        return mosipAuthService;
    }

    /**
     * Set the MOSIP auth service
     *
     * @param mosipAuthService The MOSIP auth service
     */
    public void setMOSIPAuthService(MOSIPAuthService mosipAuthService) {

        this.mosipAuthService = mosipAuthService;
    }
}