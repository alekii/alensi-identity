<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('code'); section>
    <#if section = "header">
        ${msg("alensiCodeTitle")}
    <#elseif section = "form">
        <p id="alensi-code-sent">${msg(alensiCodeSentMessage, alensiCodeDestination)}</p>
        <form id="kc-otp-login-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <label for="code" class="${properties.kcLabelClass!}">${msg("alensiCodeLabel")}</label>
                <input id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" autofocus
                       class="${properties.kcInputClass!}"
                       aria-invalid="<#if messagesPerField.existsError('code')>true</#if>"/>
                <#if messagesPerField.existsError('code')>
                    <span id="input-error-code" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                        ${kcSanitize(messagesPerField.get('code'))?no_esc}
                    </span>
                </#if>
            </div>
            <div id="kc-form-buttons" class="${properties.kcFormGroupClass!}">
                <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                       name="login" id="kc-login" type="submit" value="${msg("doSignIn")}"/>
                <button class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonBlockClass!}"
                        name="resend" id="alensi-resend" value="true" type="submit" formnovalidate>${msg("alensiCodeResend")}</button>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
