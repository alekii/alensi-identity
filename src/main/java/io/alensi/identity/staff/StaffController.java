package io.alensi.identity.staff;

import java.util.List;

import io.alensi.identity.user.UserAccount;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/tenants/{tenant}/staff")
class StaffController {

    private final StaffOnboardingService onboarding;

    StaffController(StaffOnboardingService onboarding) {
        this.onboarding = onboarding;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    StaffOnboardingService.Onboarded onboard(UserAccount caller, @PathVariable String tenant,
            @Valid @RequestBody OnboardRequest body) {
        return onboarding.onboard(caller, tenant, new StaffOnboardingService.NewStaff(body.email(), body.firstName(),
                body.lastName(), body.phoneNumber(), Boolean.TRUE.equals(body.requireAuthenticatorApp()),
                body.grants() == null ? List.of() : body.grants().stream()
                        .map(g -> new StaffOnboardingService.GrantRequest(g.application(), g.role(), g.target()))
                        .toList()));
    }

    @PostMapping("/{username}/invite")
    @ResponseStatus(HttpStatus.ACCEPTED)
    void resendInvite(UserAccount caller, @PathVariable String tenant, @PathVariable String username) {
        onboarding.resendInvite(caller, tenant, username);
    }

    /**
     * {@code phoneNumber} (E.164) enables SMS codes. {@code requireAuthenticatorApp} makes the person
     * enrol an authenticator app on first sign-in; otherwise they can use SMS or email codes.
     */
    record OnboardRequest(@NotBlank @Email @Size(max = 320) String email, @NotBlank @Size(max = 255) String firstName,
            @NotBlank @Size(max = 255) String lastName, @Pattern(regexp = "^\\+[1-9][0-9]{7,14}$") String phoneNumber,
            Boolean requireAuthenticatorApp, List<@Valid GrantBody> grants) {
    }

    /** Grants on onboarding are always on a target in the tenant. */
    record GrantBody(@NotBlank String application, @NotBlank String role, @NotBlank String target) {
    }
}
