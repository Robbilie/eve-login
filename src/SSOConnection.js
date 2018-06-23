"use strict";

const rrr = require("request-promise-native");
const speakeasy = require("speakeasy");

const { SSO } = require(".");

class SSOConnection {

    constructor (SERVER = "tranquility", args = {}) {
        this.request = rrr.defaults({
            jar: rrr.jar(),
            simple: false,
            resolveWithFullResponse: true,
            //followRedirect: false,
            followAllRedirects: true,
            ...args,
        });
        this.baseUrl = SSO[SERVER];
    }

    async getLoginToken (args) {
        const accessToken = await this.getAccessToken(args);
        if (!accessToken)
            return null;
        return this.exchangeAccessToken(accessToken);
    }

    async exchangeAccessToken (accessToken) {
        const uri = SSO.ACCESS_TOKEN_URL(this.baseUrl, accessToken);
        const response = await this.request({
            method: "GET",
            uri,
        });
        return SSO.extractAccessToken(response.request.uri.href);
    }

    async getAccessToken ({ username, password, characterName, secret }) {
        let [access_token, res] = await this.handleInitialRequest(username, password);
        if (!access_token && SSO.requiresCharacterName(res))
            [access_token, res] = await this.handleRequiresCharacterName(characterName);
        if (!access_token && SSO.requiresAuthenticator(res))
            [access_token, res] = await this.handleRequiresAuthenticator(secret);
        if (!access_token && SSO.requiresEULA(res))
            [access_token, res] = await this.handleRequiresEULA(res);
        if (!access_token)
            throw SSO.FRAGMENT_WARNING;
        return access_token;
    }

    async handleInitialRequest (UserName, Password) {
        const __RequestVerificationToken = await this.getRequestVerificationToken();
        const response = await this.request({
            method: "POST",
            uri: SSO.LOGIN_REFERER_URL(this.baseUrl),
            form: {
                UserName,
                Password,
                __RequestVerificationToken,
            }
        });

        return [SSO.extractAccessToken(response.request.uri.href), response.body];
    }

    async getRequestVerificationToken() {
        const response = await this.request({
            method: "GET",
            uri: SSO.LOGIN_REFERER_URL(this.baseUrl),
        });

        return SSO.getRequestVerificationToken(response.body);
    }

    async handleRequiresCharacterName (characterName) {
        console.log("characterName is required!");
        if (!characterName)
            throw new Error("No CharacterName set! Aborting...");

        const response = await this.request({
            method: "POST",
            uri: SSO.CONFIRM_CHARACTER_URL(this.baseUrl),
            form: {
                Challenge: characterName,
                RememberCharacterChallenge: true,
            }
        });

        return [SSO.extractAccessToken(response.request.uri.href), response.body];
    }

    async handleRequiresAuthenticator (secret) {
        console.log("Authenticator required!");
        if (!secret)
            throw new Error("No 2FA secret set! Aborting...");

        const pin = speakeasy.totp({ secret, encoding: "base32" });
        console.log(`Using pin ${pin}`);

        const response = await this.request({
            method: "POST",
            uri: SSO.CONFIRM_AUTHENTICATOR_URL(this.baseUrl),
            form: {
                Challenge: pin,
                RememberTwoFactor: true,
                command: "Continue",
            }
        });

        return [SSO.extractAccessToken(response.request.uri.href), response.body];
    }

    async handleRequiresEULA (res) {
        console.log("Eula required!");
        const eulaHash = SSO.getEulaHash(res);
        console.log(`Eula hash: ${eulaHash}`);

        const response = await this.request({
            method: "POST",
            uri: SSO.CONFIRM_EULA_URL(this.baseUrl),
            form: {
                eulaHash,
                returnUrl: SSO.CONFIRM_EULA_RETURN_URL(this.baseUrl),
                action: "Accept",
            }
        });

        return [SSO.extractAccessToken(response.request.uri.href), response.body];
    }

}

module.exports = SSOConnection;
