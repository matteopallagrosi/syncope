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

import java.io.OutputStream;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.syncope.common.keymaster.client.api.ConfParamOps;
import org.apache.syncope.common.lib.SyncopeConstants;
import org.apache.syncope.common.lib.to.EntityTO;
import org.apache.syncope.common.lib.to.GroupTO;
import org.apache.syncope.common.lib.to.TypeExtensionTO;
import org.apache.syncope.common.lib.types.AnyTypeKind;
import org.apache.syncope.common.lib.types.IdRepoEntitlement;
import org.apache.syncope.core.persistence.api.content.ContentExporter;
import org.apache.syncope.core.persistence.api.dao.AnySearchDAO;
import org.apache.syncope.core.persistence.api.dao.AnyTypeDAO;
import org.apache.syncope.core.persistence.api.dao.GroupDAO;
import org.apache.syncope.core.persistence.api.dao.NotFoundException;
import org.apache.syncope.core.persistence.api.dao.RealmDAO;
import org.apache.syncope.core.persistence.api.dao.search.AnyCond;
import org.apache.syncope.core.persistence.api.dao.search.AttrCond;
import org.apache.syncope.core.persistence.api.dao.search.OrderByClause;
import org.apache.syncope.core.persistence.api.dao.search.SearchCond;
import org.apache.syncope.core.persistence.api.entity.Realm;
import org.apache.syncope.core.persistence.api.entity.group.Group;
import org.apache.syncope.core.persistence.api.entity.group.TypeExtension;
import org.apache.syncope.core.provisioning.api.data.GroupDataBinder;
import org.apache.syncope.core.spring.security.AuthContextUtils;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;

@Transactional(readOnly = true)
public class SyncopeLogic extends AbstractLogic<EntityTO> {

    protected final RealmDAO realmDAO;

    protected final AnyTypeDAO anyTypeDAO;

    protected final GroupDAO groupDAO;

    protected final AnySearchDAO anySearchDAO;

    protected final GroupDataBinder groupDataBinder;

    protected final ConfParamOps confParamOps;

    protected final ContentExporter exporter;

    public SyncopeLogic(
            final RealmDAO realmDAO,
            final AnyTypeDAO anyTypeDAO,
            final GroupDAO groupDAO,
            final AnySearchDAO anySearchDAO,
            final GroupDataBinder groupDataBinder,
            final ConfParamOps confParamOps,
            final ContentExporter exporter) {

        this.realmDAO = realmDAO;
        this.anyTypeDAO = anyTypeDAO;
        this.groupDAO = groupDAO;
        this.anySearchDAO = anySearchDAO;
        this.groupDataBinder = groupDataBinder;
        this.confParamOps = confParamOps;
        this.exporter = exporter;
    }

    public boolean isSelfRegAllowed() {
        return confParamOps.get(AuthContextUtils.getDomain(), "selfRegistration.allowed", false, Boolean.class);
    }

    public boolean isPwdResetAllowed() {
        return confParamOps.get(AuthContextUtils.getDomain(), "passwordReset.allowed", false, Boolean.class);
    }

    public boolean isPwdResetRequiringSecurityQuestions() {
        return confParamOps.get(AuthContextUtils.getDomain(), "passwordReset.securityQuestion", true, Boolean.class);
    }

    @PreAuthorize("isAuthenticated()")
    public Pair<Integer, List<GroupTO>> searchAssignableGroups(
            final String realm,
            final String term,
            final int page,
            final int size) {

        Realm base = Optional.ofNullable(realmDAO.findByFullPath(realm)).
                orElseThrow(() -> new NotFoundException("Realm " + realm));

        AnyCond termCond;
        if (StringUtils.isNotBlank(term)) {
            termCond = new AnyCond(AttrCond.Type.ILIKE);
            termCond.setSchema("name");
            termCond.setExpression(term.replace("*", "%"));
        } else {
            termCond = new AnyCond(AttrCond.Type.ISNOTNULL);
            termCond.setSchema("key");
        }
        SearchCond searchCond = SearchCond.getLeaf(termCond);

        int count = anySearchDAO.count(base, true, SyncopeConstants.FULL_ADMIN_REALMS, searchCond, AnyTypeKind.GROUP);

        OrderByClause orderByClause = new OrderByClause();
        orderByClause.setField("name");
        orderByClause.setDirection(OrderByClause.Direction.ASC);
        List<Group> matching = anySearchDAO.search(
                base,
                true,
                SyncopeConstants.FULL_ADMIN_REALMS,
                searchCond,
                page,
                size,
                List.of(orderByClause),
                AnyTypeKind.GROUP);
        List<GroupTO> result = matching.stream().
                map(group -> groupDataBinder.getGroupTO(group, false)).collect(Collectors.toList());

        return Pair.of(count, result);
    }

    @PreAuthorize("isAuthenticated()")
    public TypeExtensionTO readTypeExtension(final String groupName) {
        Group group = groupDAO.findByName(groupName);
        if (group == null) {
            throw new NotFoundException("Group " + groupName);
        }
        Optional<? extends TypeExtension> typeExt = group.getTypeExtension(anyTypeDAO.findUser());
        if (typeExt.isEmpty()) {
            throw new NotFoundException("TypeExtension in " + groupName + " for users");
        }

        return groupDataBinder.getTypeExtensionTO(typeExt.get());
    }

    @PreAuthorize("hasRole('" + IdRepoEntitlement.KEYMASTER + "')")
    @Transactional(readOnly = true)
    public void exportInternalStorageContent(final int tableThreshold, final OutputStream os) {
        try {
            exporter.export(
                    AuthContextUtils.getDomain(),
                    tableThreshold,
                    os);
            LOG.debug("Internal storage content successfully exported");
        } catch (Exception e) {
            LOG.error("While exporting internal storage content", e);
        }
    }

    @Override
    protected EntityTO resolveReference(final Method method, final Object... args)
            throws UnresolvedReferenceException {

        throw new UnresolvedReferenceException();
    }
}
