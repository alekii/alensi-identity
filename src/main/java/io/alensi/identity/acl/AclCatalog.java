package io.alensi.identity.acl;

import java.util.Comparator;
import java.util.List;

import io.alensi.identity.user.UserAccount;
import io.alensi.identity.web.NotFoundException;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Read side of the ACL catalog. */
@Service
@Transactional(readOnly = true)
public class AclCatalog {

    private final ApplicationRepository applications;
    private final PermissionRepository permissions;
    private final RoleRepository roles;
    private final TargetTypeRepository targetTypes;
    private final TargetRepository targets;
    private final RoleGrantRepository grants;

    AclCatalog(ApplicationRepository applications, PermissionRepository permissions, RoleRepository roles,
            TargetTypeRepository targetTypes, TargetRepository targets, RoleGrantRepository grants) {
        this.applications = applications;
        this.permissions = permissions;
        this.roles = roles;
        this.targetTypes = targetTypes;
        this.targets = targets;
        this.grants = grants;
    }

    public List<AclViews.ApplicationView> applications() {
        return applications.findAll(Sort.by("code")).stream().map(AclViews.ApplicationView::of).toList();
    }

    public AclViews.ApplicationView application(String code) {
        return AclViews.ApplicationView.of(find(code));
    }

    public List<AclViews.PermissionView> permissions(String applicationCode) {
        return permissions.findByApplicationOrderByCode(find(applicationCode)).stream()
                .map(AclViews.PermissionView::of)
                .toList();
    }

    public List<AclViews.RoleView> roles(String applicationCode) {
        return roles.findByApplicationOrderByCode(find(applicationCode)).stream().map(AclViews.RoleView::of).toList();
    }

    public List<AclViews.TargetTypeView> targetTypes() {
        return targetTypes.findAll(Sort.by("code")).stream().map(AclViews.TargetTypeView::of).toList();
    }

    public List<AclViews.TargetView> targets() {
        return targets.findAllWithTypeAndParent().stream()
                .sorted(Comparator.comparing(Target::getCode))
                .map(AclViews.TargetView::of)
                .toList();
    }

    public List<AclViews.GrantView> grants(UserAccount user) {
        return grants.findForUser(user).stream().map(AclViews.GrantView::of).toList();
    }

    private Application find(String code) {
        return applications.findByCode(code)
                .orElseThrow(() -> new NotFoundException("Application '%s' not found".formatted(code)));
    }
}
