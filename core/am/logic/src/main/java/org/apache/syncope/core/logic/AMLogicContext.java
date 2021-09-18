/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.syncope.core.logic;

import org.apache.syncope.common.keymaster.client.api.ServiceOps;
import org.apache.syncope.core.logic.init.AMEntitlementLoader;
import org.apache.syncope.core.logic.wa.GoogleMfaAuthAccountLogic;
import org.apache.syncope.core.logic.wa.GoogleMfaAuthTokenLogic;
import org.apache.syncope.core.logic.wa.ImpersonationLogic;
import org.apache.syncope.core.logic.wa.U2FRegistrationLogic;
import org.apache.syncope.core.logic.wa.WAClientAppLogic;
import org.apache.syncope.core.logic.wa.WAConfigLogic;
import org.apache.syncope.core.logic.wa.WebAuthnRegistrationLogic;
import org.apache.syncope.core.persistence.api.dao.SRARouteDAO;
import org.apache.syncope.core.persistence.api.dao.auth.AuthModuleDAO;
import org.apache.syncope.core.persistence.api.dao.auth.AuthProfileDAO;
import org.apache.syncope.core.persistence.api.dao.auth.CASSPDAO;
import org.apache.syncope.core.persistence.api.dao.auth.OIDCJWKSDAO;
import org.apache.syncope.core.persistence.api.dao.auth.OIDCRPDAO;
import org.apache.syncope.core.persistence.api.dao.auth.SAML2IdPEntityDAO;
import org.apache.syncope.core.persistence.api.dao.auth.SAML2SPDAO;
import org.apache.syncope.core.persistence.api.dao.auth.SAML2SPEntityDAO;
import org.apache.syncope.core.persistence.api.dao.auth.WAConfigDAO;
import org.apache.syncope.core.persistence.api.entity.EntityFactory;
import org.apache.syncope.core.persistence.api.entity.auth.ClientAppUtilsFactory;
import org.apache.syncope.core.provisioning.api.data.AuthModuleDataBinder;
import org.apache.syncope.core.provisioning.api.data.AuthProfileDataBinder;
import org.apache.syncope.core.provisioning.api.data.ClientAppDataBinder;
import org.apache.syncope.core.provisioning.api.data.OIDCJWKSDataBinder;
import org.apache.syncope.core.provisioning.api.data.SAML2IdPEntityDataBinder;
import org.apache.syncope.core.provisioning.api.data.SAML2SPEntityDataBinder;
import org.apache.syncope.core.provisioning.api.data.SRARouteDataBinder;
import org.apache.syncope.core.provisioning.api.data.WAConfigDataBinder;
import org.apache.syncope.core.provisioning.api.data.wa.WAClientAppDataBinder;
import org.apache.syncope.core.spring.security.SecurityProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AMLogicContext {

    @Autowired
    private SecurityProperties securityProperties;

    @Autowired
    private ServiceOps serviceOps;

    @Autowired
    private AuthProfileDAO authProfileDAO;

    @Autowired
    private AuthProfileDataBinder authProfileDataBinder;

    @Autowired
    private CASSPDAO casspDAO;

    @Autowired
    private OIDCRPDAO oidcrpDAO;

    @Autowired
    private SAML2SPDAO saml2spDAO;

    @Autowired
    private EntityFactory entityFactory;

    @ConditionalOnMissingBean
    @Bean
    public AMEntitlementLoader amEntitlementLoader() {
        return new AMEntitlementLoader();
    }

    @ConditionalOnMissingBean
    @Bean
    @Autowired
    public AuthModuleLogic authModuleLogic(
            final AuthModuleDataBinder binder,
            final AuthModuleDAO authModuleDAO) {

        return new AuthModuleLogic(binder, authModuleDAO);
    }

    @ConditionalOnMissingBean
    @Bean
    @Autowired
    public AuthProfileLogic authProfileLogic() {
        return new AuthProfileLogic(authProfileDAO, authProfileDataBinder);
    }

    @ConditionalOnMissingBean
    @Bean
    @Autowired
    public ClientAppLogic clientAppLogic(
            final ClientAppUtilsFactory clientAppUtilsFactory,
            final ClientAppDataBinder binder) {

        return new ClientAppLogic(
                serviceOps,
                clientAppUtilsFactory,
                binder,
                saml2spDAO,
                oidcrpDAO,
                casspDAO,
                securityProperties);
    }

    @ConditionalOnMissingBean
    @Bean
    @Autowired
    public OIDCJWKSLogic oidcJWKSLogic(
            final OIDCJWKSDataBinder binder,
            final OIDCJWKSDAO dao) {

        return new OIDCJWKSLogic(binder, dao);
    }

    @ConditionalOnMissingBean
    @Bean
    @Autowired
    public SAML2IdPEntityLogic saml2IdPEntityLogic(
            final SAML2IdPEntityDataBinder binder,
            final SAML2IdPEntityDAO entityDAO) {

        return new SAML2IdPEntityLogic(binder, entityDAO);
    }

    @ConditionalOnMissingBean
    @Bean
    @Autowired
    public SAML2SPEntityLogic saml2SPEntityLogic(
            final SAML2SPEntityDataBinder binder,
            final SAML2SPEntityDAO entityDAO) {

        return new SAML2SPEntityLogic(binder, entityDAO);
    }

    @ConditionalOnMissingBean
    @Bean
    @Autowired
    public SRARouteLogic sraRouteLogic(
            final SRARouteDAO routeDAO,
            final SRARouteDataBinder binder) {

        return new SRARouteLogic(routeDAO, binder, entityFactory, serviceOps, securityProperties);
    }

    @ConditionalOnMissingBean
    @Bean
    public GoogleMfaAuthAccountLogic googleMfaAuthAccountLogic() {
        return new GoogleMfaAuthAccountLogic(entityFactory, authProfileDAO, authProfileDataBinder);
    }

    @ConditionalOnMissingBean
    @Bean
    public GoogleMfaAuthTokenLogic googleMfaAuthTokenLogic() {
        return new GoogleMfaAuthTokenLogic(entityFactory, authProfileDAO, authProfileDataBinder);
    }

    @ConditionalOnMissingBean
    @Bean
    public ImpersonationLogic impersonationLogic() {
        return new ImpersonationLogic(entityFactory, authProfileDAO, authProfileDataBinder);
    }

    @ConditionalOnMissingBean
    @Bean
    public U2FRegistrationLogic u2fRegistrationLogic() {
        return new U2FRegistrationLogic(entityFactory, authProfileDAO, authProfileDataBinder);
    }

    @ConditionalOnMissingBean
    @Bean
    @Autowired
    public WAClientAppLogic waClientAppLogic(final WAClientAppDataBinder binder) {
        return new WAClientAppLogic(binder, saml2spDAO, oidcrpDAO, casspDAO);
    }

    @ConditionalOnMissingBean
    @Bean
    @Autowired
    public WAConfigLogic waConfigLogic(
            final WAConfigDataBinder binder,
            final WAConfigDAO waConfigDAO) {

        return new WAConfigLogic(serviceOps, binder, waConfigDAO, securityProperties);
    }

    @ConditionalOnMissingBean
    @Bean
    public WebAuthnRegistrationLogic webAuthnRegistrationLogic() {
        return new WebAuthnRegistrationLogic(entityFactory, authProfileDAO, authProfileDataBinder);
    }
}
