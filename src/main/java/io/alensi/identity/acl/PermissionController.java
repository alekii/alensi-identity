package io.alensi.identity.acl;

import java.util.List;
import java.util.SortedMap;
import java.util.SortedSet;

import io.alensi.identity.user.AccessGuard;
import io.alensi.identity.user.UserAccount;
import io.alensi.identity.user.UserDirectory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Permission queries for a user in an application. {@code {user}} is a username or {@code me}.
 * Querying someone else requires {@code identity.permissions.read}, and answers are limited to the
 * part of the target tree the caller holds it on: a branch admin sees their staff's access in their
 * branch only.
 */
@RestController
@RequestMapping("/api/users/{user}/applications/{application}")
class PermissionController {

    private static final String ME = "me";

    private final PermissionService permissions;
    private final UserDirectory directory;
    private final AccessGuard access;

    PermissionController(PermissionService permissions, UserDirectory directory, AccessGuard access) {
        this.permissions = permissions;
        this.directory = directory;
        this.access = access;
    }

    @GetMapping("/permissions")
    SortedMap<String, SortedMap<String, SortedSet<String>>> permissions(UserAccount caller, @PathVariable String user,
            @PathVariable String application, @RequestParam(required = false) String targetCode,
            @RequestParam(required = false) String targetType, @RequestParam(defaultValue = "false") boolean compressed) {
        Query query = query(caller, user, application);
        if (targetCode != null) {
            return query.evaluator().permissionsOn(query.target(targetCode));
        }
        return query.evaluator().permissions(compressed, targetType, query.scope());
    }

    @GetMapping("/permissions/{permission}")
    Decision hasPermission(UserAccount caller, @PathVariable String user, @PathVariable String application,
            @PathVariable String permission) {
        Query query = query(caller, user, application);
        return new Decision(query.evaluator().hasPermission(permission, query.scope()));
    }

    @GetMapping("/permissions/{permission}/targets")
    List<String> permissionTargets(UserAccount caller, @PathVariable String user, @PathVariable String application,
            @PathVariable String permission, @RequestParam(defaultValue = "false") boolean compressed) {
        Query query = query(caller, user, application);
        return query.evaluator().targetsWith(permission, compressed, query.scope());
    }

    @GetMapping("/permissions/{permission}/targets/{target}")
    Decision hasPermissionOnTarget(UserAccount caller, @PathVariable String user, @PathVariable String application,
            @PathVariable String permission, @PathVariable String target) {
        Query query = query(caller, user, application);
        return new Decision(query.evaluator().hasPermission(permission, query.target(target)));
    }

    @GetMapping("/targets")
    List<TargetNode> targets(UserAccount caller, @PathVariable String user, @PathVariable String application,
            @RequestParam(required = false) String targetType) {
        Query query = query(caller, user, application);
        return query.evaluator().targets(targetType, query.scope());
    }

    private Query query(UserAccount caller, String user, String application) {
        if (ME.equals(user) || caller.getUsername().equals(user)) {
            return new Query(permissions.evaluatorFor(caller, application), Scope.ALL);
        }
        access.requireAnywhere(caller, AccessGuard.PERMISSIONS_READ);
        UserAccount subject = directory.findByUsername(user);
        Scope scope = access.readScope(caller, subject, AccessGuard.PERMISSIONS_READ);
        return new Query(permissions.evaluatorFor(subject, application), scope);
    }

    record Decision(boolean allowed) {
    }

    /** The subject's permissions and the part of them the caller may see. */
    private record Query(PermissionEvaluator evaluator, Scope scope) {

        TargetNode target(String code) {
            TargetNode target = evaluator.requireTarget(code);
            if (!scope.covers(target)) {
                throw new AccessDeniedException("Target '%s' is outside your scope".formatted(code));
            }
            return target;
        }
    }
}
