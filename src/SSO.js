"use strict";

const qs = require("qs");

class SSO {

    static get tranquility () {
        return "https://login.eveonline.com";
    }

    static get singularity () {
        return "https://sisilogin.testeveonline.com";
    }

    static extractAccessToken (url) {
        const length = url.indexOf(SSO.ACCESS_TOKEN_NEEDLE);
        if (length === -1)
            return null;
        return url.substring(length + SSO.ACCESS_TOKEN_NEEDLE.length, url.indexOf("&"));
    }

    static requiresEULA (res) {
        return res.match(new RegExp(SSO.EULA_NEEDLE, "i"));
    }

    static getEulaHash (res) {
        const hashStart = res.match(new RegExp(SSO.EULA_HASH_NEEDLE, "i"));
        if (!hashStart || hashStart.index === -1)
            throw new Error("Missing EULA Hash!");
        return res.substr(hashStart.index + SSO.EULA_HASH_NEEDLE.length, 32);
    }

    static requiresAuthenticator (res) {
        return res.match(new RegExp(SSO.AUTHENTICATOR_NEEDLE, "i"));
    }

    static requiresCharacterName (res) {
        return res.match(new RegExp(SSO.CHARACTER_NEEDLE, "g"));
    }

    static ACCOUNT_URL (baseUrl, accountUrl) {
        return `${baseUrl}${accountUrl}?${qs.stringify({
            ReturnUrl: SSO.RETURN_URL(baseUrl),
        })}`;
    }

    static LOGIN_REFERER_URL (baseUrl) {
        return SSO.ACCOUNT_URL(baseUrl, "/Account/LogOn");
    }

    static RETURN_URL (baseUrl) {
        return `/oauth/authorize/?${qs.stringify({
            client_id: "eveLauncherTQ",
            lang: "en",
            response_type: "token",
            redirect_uri: `${baseUrl}/launcher?${qs.stringify({
                client_id: "eveLauncherTQ",
                scope: "eveClientToken"
            })}`,
        }, { encode: false })}`;
    }

    static CONFIRM_CHARACTER_URL (baseUrl) {
        return SSO.ACCOUNT_URL(baseUrl, "/Account/Challenge");
    }

    static CONFIRM_AUTHENTICATOR_URL (baseUrl) {
        return SSO.ACCOUNT_URL(baseUrl, "/Account/Authenticator");
    }

    static CONFIRM_EULA_URL (baseUrl) {
        return `${baseUrl}/OAuth/Eula`;
    }

    static CONFIRM_EULA_RETURN_URL (baseUrl) {
        return SSO.RETURN_URL(baseUrl);
    }

    static ACCESS_TOKEN_URL (baseUrl, accessToken) {
        return `${baseUrl}/launcher/token?accesstoken=${accessToken}`;
    }

}

SSO.FRAGMENT_WARNING = `No Fragment found. 
Make sure your login details are correct and your system clock is correct when using authenticator. 
If you believe it's not your fault please report this issue.`;
SSO.CHARACTER_NEEDLE = "please enter the name of one of the characters associated with your account";
SSO.AUTHENTICATOR_NEEDLE = "action=\"/Account/Authenticator";
SSO.EULA_NEEDLE = "action=\"/oauth/eula\"";
SSO.EULA_HASH_NEEDLE = "name=\"eulaHash\" type=\"hidden\" value=\"";
SSO.ACCESS_TOKEN_NEEDLE = "#access_token=";

module.exports = SSO;
