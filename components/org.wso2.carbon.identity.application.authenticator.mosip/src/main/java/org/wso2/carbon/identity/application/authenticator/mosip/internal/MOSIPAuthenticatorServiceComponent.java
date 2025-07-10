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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.mosip.MOSIPAuthenticator;
import org.wso2.carbon.identity.application.authenticator.mosip.service.MOSIPAuthService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * OSGi service component for the MOSIP Authenticator.
 * This component registers and manages the MOSIP authenticator service.
 */
@Component(
        name = "org.wso2.carbon.identity.application.authenticator.mosip",
        immediate = true
)
public class MOSIPAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(MOSIPAuthenticatorServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            // Get service instances from the service holder
            MOSIPAuthService mosipAuthService = MOSIPAuthenticatorServiceDataHolder.getInstance().getMOSIPAuthService();

            // Create the authenticator with the service instances
            MOSIPAuthenticator mosipAuthenticator = new MOSIPAuthenticator(mosipAuthService);

            // Register the authenticator as an OSGi service
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), mosipAuthenticator, null);

            if (log.isDebugEnabled()) {
                log.debug("MOSIP Authenticator bundle is activated");
            }
        } catch (Throwable e) {
            log.error("Error while activating MOSIP Authenticator bundle", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.debug("MOSIP Authenticator bundle is deactivated");
        }
    }

    @Reference(
            name = "identity.application.authenticator.framework",
            service = ApplicationAuthenticator.class,
            cardinality = ReferenceCardinality.AT_LEAST_ONE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetAuthenticator"
    )
    protected void setAuthenticator(ApplicationAuthenticator authenticator) {

        if (log.isDebugEnabled()) {
            log.debug("Setting authenticator: " + authenticator.getName());
        }
        MOSIPAuthenticatorServiceDataHolder.getInstance().addAuthenticator(authenticator);
    }

    protected void unsetAuthenticator(ApplicationAuthenticator authenticator) {

        if (log.isDebugEnabled()) {
            log.debug("Unsetting authenticator: " + authenticator.getName());
        }
        MOSIPAuthenticatorServiceDataHolder.getInstance().removeAuthenticator(authenticator);
    }

    @Reference(
            name = "realm.service",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service");
        }
        MOSIPAuthenticatorServiceDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Unsetting the Realm Service");
        }
        MOSIPAuthenticatorServiceDataHolder.getInstance().setRealmService(null);
    }
}