package org.jenkinsci.plugins.oic.plugintest;

import java.util.ArrayList;
import java.util.List;
import jenkins.security.SecurityListener;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Captures every {@link SecurityListener} callback by username, so a test can assert exactly
 * which events fired (or didn't) for a given HTTP interaction, not just the end-to-end HTTP
 * outcome {@code PluginTestHelper}/{@code PluginTestAsserts} already check.
 */
public abstract class SecurityListenerSpy extends SecurityListener {
    public final List<String> authenticated2 = new ArrayList<>();
    public final List<String> loggedIn = new ArrayList<>();
    public final List<String> failedToAuthenticate = new ArrayList<>();
    public final List<String> failedToLogIn = new ArrayList<>();
    public final List<String> loggedOut = new ArrayList<>();

    public void clear() {
        authenticated2.clear();
        loggedIn.clear();
        failedToAuthenticate.clear();
        failedToLogIn.clear();
        loggedOut.clear();
    }

    public int totalFireCount() {
        return authenticated2.size()
                + loggedIn.size()
                + failedToAuthenticate.size()
                + failedToLogIn.size()
                + loggedOut.size();
    }

    @Override
    protected void authenticated2(UserDetails details) {
        authenticated2.add(details.getUsername());
    }

    @Override
    protected void loggedIn(String username) {
        loggedIn.add(username);
    }

    @Override
    protected void failedToAuthenticate(String username) {
        failedToAuthenticate.add(username);
    }

    @Override
    protected void failedToLogIn(String username) {
        failedToLogIn.add(username);
    }

    @Override
    protected void loggedOut(String username) {
        loggedOut.add(username);
    }
}
