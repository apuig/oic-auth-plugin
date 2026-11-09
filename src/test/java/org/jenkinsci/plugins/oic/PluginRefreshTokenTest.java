package org.jenkinsci.plugins.oic;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.notMatching;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.jenkinsci.plugins.oic.TestRealm.EMAIL_FIELD;
import static org.jenkinsci.plugins.oic.TestRealm.GROUPS_FIELD;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestAsserts.assertTestUser;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_USER_USERNAME;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.browseLoginPage;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.configureWellKnown;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.expire;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.getPageWithGet;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.getUserInfo;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.isDebuggingEnabled;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.setUpKeyValuesWithGroup;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockAuthorizationRedirectsToFinishLogin;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockTokenReturnsIdTokenWithGroup;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockTokenReturnsIdTokenWithValues;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockTokenReturnsIdTokenWithoutValues;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockUserInfo;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockUserInfoWithGroups;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockUserInfoWithTestGroups;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.nimbusds.oauth2.sdk.GrantType;
import hudson.ExtensionList;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.oic.plugintest.PluginTestHelper;
import org.jenkinsci.plugins.oic.plugintest.SecurityListenerSpy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.TestExtension;
import org.jvnet.hudson.test.Url;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * goes through a login scenario, the openid provider is mocked and always
 * returns state. We aren't checking if openid connect or if the openid
 * connect implementation works. Rather we are only checking if the jenkins
 * interaction works and if the plugin code works.
 */
@Url("https://jenkins.io/blog/2018/01/13/jep-200/")
@WithJenkins
public class PluginRefreshTokenTest {

    private static final String[] TEST_USER_GROUPS_REFRESHED = new String[] {"group1", "group2", "group3"};

    @RegisterExtension
    static WireMockExtension wireMock = WireMockExtension.newInstance()
            .failOnUnmatchedRequests(true)
            .options(wireMockConfig().dynamicPort().dynamicHttpsPort())
            .build();

    private JenkinsRule jenkinsRule;
    private JenkinsRule.WebClient webClient;
    private Jenkins jenkins;
    private SecurityListenerSpy spy;

    @BeforeEach
    void setUp(JenkinsRule jenkinsRule) {
        this.jenkinsRule = jenkinsRule;
        jenkins = jenkinsRule.getInstance();
        webClient = jenkinsRule.createWebClient();
        if (isDebuggingEnabled()) {
            webClient.getOptions().setTimeout(0);
        }
        spy = ExtensionList.lookupSingleton(SpyImpl.class);
        spy.clear();
    }

    @TestExtension
    public static class SpyImpl extends SecurityListenerSpy {}

    @Test
    void testConfigurationWithAutoConfiguration_withRefreshToken() throws Exception {
        configureWellKnown(wireMock, null, null, "authorization_code", "refresh_token");
        TestRealm testRealm = new TestRealm.Builder(wireMock)
                .WithMinimalDefaults().WithAutomanualconfigure(true).build();
        jenkins.setSecurityRealm(testRealm);
        assertTrue(
                testRealm
                        .getServerConfiguration()
                        .toProviderMetadata()
                        .getGrantTypes()
                        .contains(GrantType.REFRESH_TOKEN),
                "Refresh token should be enabled");
    }

    @Test
    void testRefreshToken_validAndExtendedToken() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        configureWellKnown(wireMock, null, null, "authorization_code", "refresh_token");
        jenkins.setSecurityRealm(new TestRealm(wireMock, null, EMAIL_FIELD, GROUPS_FIELD, true));
        // user groups on first login
        mockTokenReturnsIdTokenWithGroup(wireMock);
        mockUserInfoWithTestGroups(wireMock);
        browseLoginPage(webClient, jenkins);
        var user = assertTestUser(webClient);
        assertFalse(
                user.getAuthorities().contains(TEST_USER_GROUPS_REFRESHED[2]),
                "User should not be part of group " + TEST_USER_GROUPS_REFRESHED[2]);
        assertEquals(List.of(TEST_USER_USERNAME), spy.authenticated2, "real login should fire authenticated2 once");
        assertEquals(List.of(TEST_USER_USERNAME), spy.loggedIn, "real login should fire loggedIn once");
        spy.clear();

        // refresh user with different groups
        mockTokenReturnsIdTokenWithValues(wireMock, setUpKeyValuesWithGroup(TEST_USER_GROUPS_REFRESHED));
        mockUserInfoWithGroups(wireMock, TEST_USER_GROUPS_REFRESHED);
        expire(webClient);
        webClient.goTo(jenkins.getSearchUrl());

        user = assertTestUser(webClient);
        assertTrue(
                user.getAuthorities().contains(TEST_USER_GROUPS_REFRESHED[2]),
                "User should be part of group " + TEST_USER_GROUPS_REFRESHED[2]);

        wireMock.verify(
                postRequestedFor(urlPathEqualTo("/token")).withRequestBody(containing("grant_type=refresh_token")));
        // A silent refresh, triggered by an ordinary page view with no login action, re-fires
        // authenticated2+loggedIn exactly as a fresh login would.
        assertEquals(
                List.of(TEST_USER_USERNAME), spy.authenticated2, "silent refresh should re-fire authenticated2 once");
        assertEquals(List.of(TEST_USER_USERNAME), spy.loggedIn, "silent refresh should re-fire loggedIn once");
    }

    @Test
    void testRefreshTokenAndTokenExpiration_withoutRefreshToken() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        configureWellKnown(wireMock, null, null, "authorization_code");
        jenkins.setSecurityRealm(new TestRealm(wireMock, null, EMAIL_FIELD, GROUPS_FIELD, true));
        // login
        mockTokenReturnsIdTokenWithGroup(wireMock, PluginTestHelper::withoutRefreshToken);
        mockUserInfoWithTestGroups(wireMock);
        browseLoginPage(webClient, jenkins);
        assertTestUser(webClient);
        spy.clear();
        // expired token not refreshed
        expire(webClient);
        // use an actual HttpClient to make checking redirects easier
        HttpResponse<String> rsp = getPageWithGet(jenkinsRule, "/manage");
        assertThat("response should have been 302\n" + rsp.body(), rsp.statusCode(), is(302));
        wireMock.verify(postRequestedFor(urlPathEqualTo("/token"))
                .withRequestBody(notMatching(".*grant_type=refresh_token.*")));
        // No refresh token: handleTokenExpiration redirects straight to the login URL without
        // attempting a refresh. A 302, and zero SecurityListener events.
        assertEquals(0, spy.totalFireCount(), "no SecurityListener event should fire when there's no refresh token");
    }

    @Test
    void testRefreshTokenWithTokenExpirationCheckDisabled_withoutRefreshToken() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        configureWellKnown(wireMock, null, null, "authorization_code");
        var realm = new TestRealm(wireMock, null, EMAIL_FIELD, GROUPS_FIELD, true);
        realm.setTokenExpirationCheckDisabled(true);
        jenkins.setSecurityRealm(realm);
        // login
        mockTokenReturnsIdTokenWithoutValues(wireMock);
        mockUserInfoWithTestGroups(wireMock);
        browseLoginPage(webClient, jenkins);
        assertTestUser(webClient);
        spy.clear();

        expire(webClient);
        webClient.goTo(jenkins.getSearchUrl());

        wireMock.verify(postRequestedFor(urlPathEqualTo("/token"))
                .withRequestBody(notMatching(".*grant_type=refresh_token.*")));
        // No refresh attempted, expiration check disabled: the expired token is let through as
        // if it were still valid. No new SecurityListener event, since no new authentication
        // happens.
        assertEquals(
                0,
                spy.totalFireCount(),
                "no SecurityListener event should fire when an unrefreshable token is let through unchecked");
    }

    @Test
    void testRefreshTokenWithTokenExpirationCheckDisabled_expiredRefreshToken() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        configureWellKnown(wireMock, null, null, "authorization_code", "refresh_token");
        TestRealm testRealm = new TestRealm(wireMock, null, EMAIL_FIELD, GROUPS_FIELD, true);
        testRealm.setTokenExpirationCheckDisabled(true);
        jenkins.setSecurityRealm(testRealm);
        // login
        mockTokenReturnsIdTokenWithGroup(wireMock);
        mockUserInfoWithTestGroups(wireMock);
        browseLoginPage(webClient, jenkins);
        assertTestUser(webClient);
        spy.clear();

        wireMock.stubFor(post(urlPathEqualTo("/token"))
                .willReturn(aResponse()
                        .withStatus(400)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{ \"error\": \"invalid_grant\" }")));
        expire(webClient);
        webClient.goTo(jenkins.getSearchUrl(), "");

        wireMock.verify(
                postRequestedFor(urlPathEqualTo("/token")).withRequestBody(containing("grant_type=refresh_token")));
        // Refresh is attempted and rejected (invalid_grant), but expiration check is disabled, so
        // refreshExpiredToken swallows it silently instead of redirecting. No SecurityListener
        // event either way.
        assertEquals(
                0,
                spy.totalFireCount(),
                "no SecurityListener event should fire when a disabled expiration check swallows an invalid_grant");
    }

    @Test
    void testRefreshTokenAndTokenExpiration_expiredRefreshToken() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        configureWellKnown(wireMock, null, null, "authorization_code", "refresh_token");
        TestRealm testRealm = new TestRealm(wireMock, null, EMAIL_FIELD, GROUPS_FIELD, true);
        jenkins.setSecurityRealm(testRealm);
        // login
        mockTokenReturnsIdTokenWithGroup(wireMock);
        mockUserInfoWithTestGroups(wireMock);
        browseLoginPage(webClient, jenkins);
        assertTestUser(webClient);
        spy.clear();

        wireMock.stubFor(post(urlPathEqualTo("/token"))
                .willReturn(aResponse()
                        .withStatus(400)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{ \"error\": \"invalid_grant\" }")));
        expire(webClient);
        webClient.assertFails(jenkins.getSearchUrl(), 500);

        wireMock.verify(
                postRequestedFor(urlPathEqualTo("/token")).withRequestBody(containing("grant_type=refresh_token")));
        // Distinct from the "no refresh token" case above: here a refresh token exists and is
        // tried, but the IdP rejects it (invalid_grant), surfacing as a 500 instead of a 302.
        // Equally silent either way: zero SecurityListener events.
        assertEquals(0, spy.totalFireCount(), "no SecurityListener event should fire when the IdP rejects the refresh");
    }

    @Test
    void testRefreshToken_usernameChangedOnRefresh() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        configureWellKnown(wireMock, null, null, "authorization_code", "refresh_token");
        TestRealm testRealm = new TestRealm(wireMock, null, EMAIL_FIELD, GROUPS_FIELD, true);
        jenkins.setSecurityRealm(testRealm);
        // login
        mockTokenReturnsIdTokenWithGroup(wireMock);
        mockUserInfoWithTestGroups(wireMock);
        browseLoginPage(webClient, jenkins);
        assertTestUser(webClient);
        spy.clear();

        // Override "sub" in both the refreshed id_token and the /userinfo response:
        // determineStringField checks userinfo before the id_token, so overriding the id_token
        // alone would not trigger the mismatch.
        mockTokenReturnsIdTokenWithValues(wireMock, Map.of("sub", "someone-else"));
        var mismatchedUserInfo = getUserInfo(wireMock, null, false);
        mismatchedUserInfo.put("sub", "someone-else");
        mockUserInfo(wireMock, mismatchedUserInfo);
        expire(webClient);
        webClient.assertFails(jenkins.getSearchUrl(), 401);

        wireMock.verify(
                postRequestedFor(urlPathEqualTo("/token")).withRequestBody(containing("grant_type=refresh_token")));
        // refreshExpiredToken's username-mismatch guard rejects the refresh with 401, but like
        // every refresh failure above, without calling failedToAuthenticate/failedToLogIn.
        assertEquals(
                0, spy.totalFireCount(), "no SecurityListener event should fire when a refresh changes the username");
    }
}
