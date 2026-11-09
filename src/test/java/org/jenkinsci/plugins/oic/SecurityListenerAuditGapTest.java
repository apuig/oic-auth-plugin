package org.jenkinsci.plugins.oic;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestAsserts.assertAnonymous;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.belongsToGroup;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.configureTestRealm;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestHelper.configureWellKnown;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockAuthorizationRedirectsToFinishLogin;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockTokenReturnsIdToken;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockTokenReturnsIdTokenWithGroup;
import static org.jenkinsci.plugins.oic.plugintest.PluginTestMocks.mockUserInfoWithTestGroups;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import hudson.ExtensionList;
import java.util.List;
import jenkins.model.Jenkins;
import org.htmlunit.FailingHttpStatusCodeException;
import org.htmlunit.HttpMethod;
import org.htmlunit.WebRequest;
import org.htmlunit.util.NameValuePair;
import org.jenkinsci.plugins.oic.plugintest.SecurityListenerSpy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.TestExtension;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * Covers the {@code SecurityListener} firing gaps that {@link PluginTest}/{@link PluginRefreshTokenTest}
 * don't: Escape Hatch (success and failure), a {@code finishLogin} cold hit with no matching
 * {@code state}, an invalid {@code id_token}, and a {@code tokenFieldToCheck} mismatch. Each is
 * expected to fire nothing at all; that's the gap being documented, not a bug in the test.
 */
@WithJenkins
class SecurityListenerAuditGapTest {

    @RegisterExtension
    static WireMockExtension wireMock = WireMockExtension.newInstance()
            .failOnUnmatchedRequests(true)
            .options(wireMockConfig().dynamicPort().dynamicHttpsPort())
            .build();

    private JenkinsRule j;
    private Jenkins jenkins;
    private JenkinsRule.WebClient webClient;
    private SecurityListenerSpy spy;

    @BeforeEach
    void setUp(JenkinsRule rule) {
        j = rule;
        jenkins = rule.getInstance();
        webClient = rule.createWebClient();
        spy = ExtensionList.lookupSingleton(SpyImpl.class);
        spy.clear();
    }

    @Test
    void escapeHatchSuccessFiresAuthenticated2AndLoggedIn() throws Exception {
        configureWellKnown(wireMock, null, null);
        var realm = new TestRealm.Builder(wireMock)
                .WithMinimalDefaults()
                        .WithEscapeHatch(true, "hatchuser", "hatchpass", null)
                        .build();
        jenkins.setSecurityRealm(realm);

        postEscapeHatchLogin("hatchuser", "hatchpass");

        assertEquals(
                List.of("hatchuser"),
                spy.authenticated2,
                "a correct escape hatch login should fire authenticated2 once");
        assertEquals(
                List.of("hatchuser"), spy.loggedIn, "a correct escape hatch login should also fire loggedIn, via core");
    }

    @Test
    void escapeHatchWrongPasswordFiresNothing() throws Exception {
        configureWellKnown(wireMock, null, null);
        var realm = new TestRealm.Builder(wireMock)
                .WithMinimalDefaults()
                        .WithEscapeHatch(true, "hatchuser", "hatchpass", null)
                        .build();
        jenkins.setSecurityRealm(realm);

        postEscapeHatchLogin("hatchuser", "wrong-password");

        assertEquals(
                0,
                spy.totalFireCount(),
                "EscapeHatch#authenticate throws BadCredentialsException with no fire call of any kind");
    }

    @Test
    void finishLoginColdHitFiresNothing() throws Exception {
        configureWellKnown(wireMock, null, null);
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        var realm = new TestRealm.Builder(wireMock).WithMinimalDefaults().build();
        jenkins.setSecurityRealm(realm);

        // No prior commenceLogin, so no state was stashed in this session. This is a GET, so
        // Jenkins' CrumbFilter never checks it (it only checks POSTs); it's pac4j's own state
        // check in client.getCredentials(ctx) that rejects it, before loginAndSetUserData.
        assertThrows(
                FailingHttpStatusCodeException.class,
                () -> webClient.goTo("securityRealm/finishLogin"),
                "a finishLogin hit with no matching session state should fail, not silently succeed");

        assertEquals(0, spy.totalFireCount(), "a finishLogin cold hit should never reach loginAndSetUserData at all");
    }

    @Test
    void invalidIdTokenFiresNothing() throws Exception {
        configureWellKnown(wireMock, null, null);
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        mockTokenReturnsIdToken(wireMock, "not-a-valid-jwt");
        var realm = new TestRealm.Builder(wireMock).WithMinimalDefaults().build();
        jenkins.setSecurityRealm(realm);

        assertThrows(
                FailingHttpStatusCodeException.class,
                () -> webClient.goTo(jenkins.getSecurityRealm().getLoginUrl()),
                "an unparsable id_token should fail the login, not silently succeed");

        assertEquals(0, spy.totalFireCount(), "an invalid id_token should fail before authenticated2 ever fires");
    }

    @Test
    void tokenFieldToCheckMismatchFiresNothing() throws Exception {
        configureWellKnown(wireMock, null, null);
        mockAuthorizationRedirectsToFinishLogin(wireMock, jenkins);
        // The mocked token only ever carries group1/group2 (see PluginTestConstants.TEST_USER_GROUPS);
        // requiring a group it doesn't have reproduces a real tokenFieldToCheck mismatch.
        mockTokenReturnsIdTokenWithGroup(wireMock);
        mockUserInfoWithTestGroups(wireMock);
        configureTestRealm(wireMock, jenkins, belongsToGroup("group-the-token-does-not-have"));

        assertAnonymous(webClient);
        assertThrows(
                FailingHttpStatusCodeException.class,
                () -> webClient.goTo(jenkins.getSecurityRealm().getLoginUrl()),
                "a tokenFieldToCheck mismatch should fail the login, not silently succeed");

        assertEquals(
                0, spy.totalFireCount(), "a tokenFieldToCheck mismatch should fail before authenticated2 ever fires");
    }

    /**
     * Posts directly to {@code securityRealm/escapeHatch}, exempt from crumb checks by
     * {@link org.jenkinsci.plugins.oic.properties.EscapeHatch.CrumbExclusionImpl}.
     *
     * <p>Posted with no crumb at all, which only works because the pinned jenkins-core (2.539)'s
     * {@code AuthenticationProcessingFilter2} has no crumb check in {@code attemptAuthentication()};
     * a newer core adds one there, independent of the {@code CrumbExclusion} SPI above. A
     * {@code jenkins.version} bump past that point would fail
     * {@code escapeHatchSuccessFiresAuthenticated2AndLoggedIn} outright, and make
     * {@code escapeHatchWrongPasswordFiresNothing} pass for the wrong reason (blocked by the
     * crumb gate, never reaching {@code EscapeHatch#authenticate}).
     */
    private void postEscapeHatchLogin(String username, String password) throws Exception {
        // establish a session before the login POST, same as a real browser would have from
        // simply loading any earlier page
        webClient.getPage(j.getURL());
        var request = new WebRequest(
                j.getURL().toURI().resolve("securityRealm/escapeHatch").toURL(), HttpMethod.POST);
        request.setRequestParameters(
                List.of(new NameValuePair("j_username", username), new NameValuePair("j_password", password)));
        try {
            webClient.getPage(request);
        } catch (FailingHttpStatusCodeException e) {
            // Both outcomes land here: success redirects back to the page the user was on,
            // failure redirects to loginError. Only whether SecurityListener fired matters to
            // these tests, not the redirect target, so any status past the POST itself
            // (including a SuspiciousRequestFilter 400 on the loginError redirect) is fine.
        }
    }

    @TestExtension
    public static class SpyImpl extends SecurityListenerSpy {}
}
