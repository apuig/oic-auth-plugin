package org.jenkinsci.plugins.oic;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestAsserts.assertTestUser;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestConstants.TEST_USER_USERNAME;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.browseLoginPage;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.configureWellKnown;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.expire;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.getPageWithGet;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.isDebuggingEnabled;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockAuthorizationRedirectsToFinishLogin;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockTokenReturnsIdTokenWithGroup;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockUserInfoWithTestGroups;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import hudson.ExtensionList;
import hudson.model.User;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.util.List;
import jenkins.model.Jenkins;
import jenkins.security.ApiTokenProperty;
import org.jenkinsci.plugins.oic.plugintest.PluginTestHelper;
import org.jenkinsci.plugins.oic.plugintest.SecurityListenerSpy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.TestExtension;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * goes through a login scenario, the openid provider is mocked and always
 * returns state. We aren't checking if openid connect or if the openid
 * connect implementation works. Rather we are only checking if the jenkins
 * interaction works and if the plugin code works.
 */
@WithJenkins
public class PluginApiTokenTest {

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
    void testAccessJenkinsUsingApiTokens() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        configureWellKnown(wireMock, null, null, "authorization_code");

        TestRealm testRealm = new TestRealm.Builder(wireMock)
                .WithMinimalDefaults()
                        .WithAutomanualconfigure(true)
                        // explicitly ensure allowTokenAccessWithoutOicSession is disabled
                        .WithAllowTokenAccessWithoutOicSession(false)
                        .build();

        jenkins.setSecurityRealm(testRealm);

        // login and assert normal auth is working
        mockTokenReturnsIdTokenWithGroup(wireMock, PluginTestHelper::withoutRefreshToken);
        mockUserInfoWithTestGroups(wireMock);
        browseLoginPage(webClient, jenkins);
        assertTestUser(webClient);
        assertEquals(List.of(TEST_USER_USERNAME), spy.authenticated2, "OIDC login should fire authenticated2 once");
        assertEquals(List.of(TEST_USER_USERNAME), spy.loggedIn, "OIDC login should fire loggedIn once");
        spy.clear();

        // create a jenkins api token for the test user
        User userById = User.getById(TEST_USER_USERNAME, false);
        assertNotNull(userById);
        String token = userById.getProperty(ApiTokenProperty.class).generateNewToken("foo").plainValue;

        // validate that the token can be used
        HttpResponse<String> rsp = getPageWithGet(jenkinsRule, TEST_USER_USERNAME, token, "/whoAmI/api/xml");
        assertThat("response should have been 200\n" + rsp.body(), rsp.statusCode(), is(200));

        assertThat(
                "response should have been 200\n" + rsp.body(),
                rsp.body(),
                containsString("<authenticated>true</authenticated>"));
        // core's Basic-auth filter fires authenticated2 for the token; API tokens never fire loggedIn
        assertEquals(
                List.of(TEST_USER_USERNAME),
                spy.authenticated2,
                "a valid API token request should fire authenticated2 once");
        assertTrue(spy.loggedIn.isEmpty(), "API tokens never fire loggedIn");
        spy.clear();

        // expired oic session tokens, do not refreshed
        expire(webClient);

        // the default behavior expects there to be a valid oic session, so token based access
        // should now fail (unauthorized). Same authenticated2-fires-anyway shape as
        // apiTokenFiresAuthenticated2ForARequestTheRealmThenRedirects below; not re-asserted here.
        rsp = getPageWithGet(jenkinsRule, TEST_USER_USERNAME, token, "/whoAmI/api/xml");
        assertThat("response should have been 302\n" + rsp.body(), rsp.statusCode(), is(302));
        spy.clear();

        // enable "traditional api token access"
        testRealm.setAllowTokenAccessWithoutOicSession(true);

        // verify that jenkins api token is now working again
        rsp = getPageWithGet(jenkinsRule, TEST_USER_USERNAME, token, "/whoAmI/api/xml");
        assertThat("response should have been 200\n" + rsp.body(), rsp.statusCode(), is(200));
        assertThat(
                "response should have been 200\n" + rsp.body(),
                rsp.body(),
                containsString("<authenticated>true</authenticated>"));
        assertEquals(
                List.of(TEST_USER_USERNAME),
                spy.authenticated2,
                "api token access without an oic session should fire authenticated2 once");
        assertTrue(spy.loggedIn.isEmpty(), "API tokens never fire loggedIn");
        spy.clear();

        // logout
        rsp = getPageWithGet(jenkinsRule, TEST_USER_USERNAME, token, "/logout");
        assertThat("response should have been 200\n" + rsp.body(), rsp.statusCode(), is(200));
        assertEquals(
                List.of(TEST_USER_USERNAME),
                spy.loggedOut,
                "Jenkins#doLogout should fire loggedOut after the realm's own doLogout runs");
    }

    // Repeats testAccessJenkinsUsingApiTokens' login/token/expire('/whoAmI/api/xml' -> 302) setup
    // on purpose, to add the spy assertions below; could be folded into that test instead.
    @Test
    void apiTokenFiresAuthenticated2ForARequestTheRealmThenRedirects() throws Exception {
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        configureWellKnown(wireMock, null, null, "authorization_code");

        TestRealm testRealm = new TestRealm.Builder(wireMock)
                .WithMinimalDefaults()
                        .WithAutomanualconfigure(true)
                        // explicitly ensure allowTokenAccessWithoutOicSession is disabled
                        .WithAllowTokenAccessWithoutOicSession(false)
                        .build();

        jenkins.setSecurityRealm(testRealm);

        // login and assert normal auth is working
        mockTokenReturnsIdTokenWithGroup(wireMock, PluginTestHelper::withoutRefreshToken);
        mockUserInfoWithTestGroups(wireMock);
        browseLoginPage(webClient, jenkins);
        assertTestUser(webClient);

        // create a jenkins api token for the test user
        User userById = User.getById(TEST_USER_USERNAME, false);
        assertNotNull(userById);
        String token = userById.getProperty(ApiTokenProperty.class).generateNewToken("foo").plainValue;
        spy.clear();

        // expired oic session, no refresh token available
        expire(webClient);

        // Core's Basic-auth filter (BasicHeaderApiTokenAuthenticator) runs first on this request
        // and fires authenticated2 for the token; handleTokenExpiration then redirects it anyway.
        // Use Redirect.NEVER to observe the 302 directly instead of whatever it redirects to.
        HttpResponse<String> rsp =
                getPageWithGet(jenkinsRule, TEST_USER_USERNAME, token, "/whoAmI/api/xml", HttpClient.Redirect.NEVER);
        assertThat("response should have been 302\n" + rsp.body(), rsp.statusCode(), is(302));

        assertEquals(
                List.of(TEST_USER_USERNAME),
                spy.authenticated2,
                "authenticated2 should fire for the token even though it gets refused");
        assertTrue(spy.loggedIn.isEmpty(), "API tokens never fire loggedIn");
    }
}
