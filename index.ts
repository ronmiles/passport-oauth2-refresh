import oauth2 from "passport-azure-ad-oauth2";
import { HttpsProxyAgent } from "https-proxy-agent";
import OAuth2Strategy, { Strategy, StrategyOptions } from "passport-oauth2";
import { OAuth2 } from "oauth";
import { UnprotectedOAuth2Strategy } from "./OAuth2Strategy";

class AuthTokenRefresh {
  public _strategies: OAuth2Strategy[];
  public use(name: string, strategy: UnprotectedOAuth2Strategy): void {
    // if (arguments.length === 1) {
    //   strategy = name;
    //   name = strategy && strategy.name;
    // }

    if (strategy === null) {
      throw new Error("Cannot register: strategy is null");
    }

    if (!name) {
      throw new Error(
        "Cannot register: name must be specified, or strategy must include name"
      );
    }

    if (!strategy._oauth2) {
      throw new Error("Cannot register: not an OAuth2 strategy");
    }

    this._strategies[name] = {
      strategy: strategy,
      refreshOAuth2: new OAuth2(
        strategy._oauth2._clientId,
        strategy._oauth2._clientSecret,
        strategy._oauth2._baseSite,
        strategy._oauth2._authorizeUrl,
        strategy._refreshURL || strategy._oauth2._accessTokenUrl,
        strategy._oauth2._customHeaders
      ),
    };

    // if (process.env["https_proxy"]) {
    const httpsProxyAgent = new HttpsProxyAgent("http://10.0.0.10:80");
    this._strategies[name].refreshOAuth2.setAgent(httpsProxyAgent);
    // }

    this._strategies[name].refreshOAuth2.getOAuthAccessToken =
      strategy._oauth2.getOAuthAccessToken;
  }

  public has(name: string) {
    return !!this._strategies[name];
  }

  public requestNewAccessToken(
    name: string,
    refreshToken: string,
    params: any,
    done: Function
  ) {
    if (arguments.length === 3) {
      done = params;
      params = {};
    }

    // Send a request to refresh an access token, and call the passed
    // callback with the result.
    const strategy = this._strategies[name];
    if (!strategy) {
      return done(new Error("Strategy was not registered to refresh a token"));
    }

    params = params || {};
    params.grant_type = "refresh_token";

    strategy.refreshOAuth2.getOAuthAccessToken(refreshToken, params, done);
  }

  private setProxy(name: string, host: string) {
    const httpsProxyAgent = new HttpsProxyAgent(host);
    this._strategies[name]._oauth2.setAgent(httpsProxyAgent);
  }
}

export default AuthTokenRefresh;
