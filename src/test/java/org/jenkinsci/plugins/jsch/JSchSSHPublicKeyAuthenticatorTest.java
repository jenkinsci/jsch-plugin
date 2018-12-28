/*
 * The MIT License
 *
 * Copyright (c) 2011-2012, CloudBees, Inc., Stephen Connolly.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins.jsch;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHAuthenticator;
import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey;
import com.cloudbees.plugins.credentials.CredentialsScope;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.pubkey.UserAuthPublicKeyFactory;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class JSchSSHPublicKeyAuthenticatorTest {

    private KeyPair keyPair;

    private JSchConnector connector;
    private SSHUserPrivateKey user;

    @Rule public JenkinsRule r = new JenkinsRule();

    @After
    public void tearDown() throws Exception {
        if (connector != null) {
            connector.close();
            connector = null;
        }
    }

    @Before
    public void setUp() throws Exception {
        KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
        rsaGenerator.initialize(4096);
        keyPair = rsaGenerator.genKeyPair();
        BasicSSHUserPrivateKey.PrivateKeySource privateKeySource =
                new BasicSSHUserPrivateKey.DirectEntryPrivateKeySource(encodeKeyToPemForm(keyPair.getPrivate()));
        user = new BasicSSHUserPrivateKey(CredentialsScope.SYSTEM, "foobar", "foobar", privateKeySource, null, null);
    }

    @Test
    public void testAuthenticate() throws Exception {
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPort(0);
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());
        sshd.setPublickeyAuthenticator((username, key, session) -> username.equals("foobar") && Arrays.equals(key.getEncoded(), keyPair.getPublic().getEncoded()));
        sshd.setUserAuthFactories(Collections.singletonList(new UserAuthPublicKeyFactory()));
        try {
            sshd.start();
            connector = new JSchConnector(user.getUsername(), "localhost", sshd.getPort());
            JSchSSHPublicKeyAuthenticator instance =
                    new JSchSSHPublicKeyAuthenticator(connector, user);
            assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.BEFORE_CONNECT));
            assertThat(instance.canAuthenticate(), is(true));
            assertThat(instance.authenticate(), is(true));
            assertThat(instance.isAuthenticated(), is(true));
            assertThat(connector.getSession().isConnected(), is(false));
            connector.getSession().setConfig("StrictHostKeyChecking", "no");
            connector.getSession().connect((int) TimeUnit.SECONDS.toMillis(30));
            assertThat(connector.getSession().isConnected(), is(true));
        } finally {
            try {
                sshd.stop(true);
            } catch (Throwable t) {
                Logger.getLogger(getClass().getName()).log(Level.WARNING, "Problems shutting down ssh server", t);
            }
        }
    }

    @Test
    public void testFactory() throws Exception {
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPort(0);
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());
        sshd.setPublickeyAuthenticator((username, key, session) -> username.equals("foobar") && Arrays.equals(key.getEncoded(), keyPair.getPublic().getEncoded()));
        sshd.setUserAuthFactories(Collections.singletonList(new UserAuthPublicKeyFactory()));
        try {
            sshd.start();
            connector = new JSchConnector(user.getUsername(), "localhost", sshd.getPort());
            SSHAuthenticator instance = SSHAuthenticator.newInstance(connector, user);
            assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.BEFORE_CONNECT));
            assertThat(instance.canAuthenticate(), is(true));
            assertThat(instance.authenticate(), is(true));
            assertThat(instance.isAuthenticated(), is(true));
            assertThat(connector.getSession().isConnected(), is(false));
            connector.getSession().setConfig("StrictHostKeyChecking", "no");
            connector.getSession().connect((int) TimeUnit.SECONDS.toMillis(30));
            assertThat(connector.getSession().isConnected(), is(true));
        } finally {
            try {
                sshd.stop(true);
            } catch (Throwable t) {
                Logger.getLogger(getClass().getName()).log(Level.WARNING, "Problems shutting down ssh server", t);
            }
        }
    }

    private static String encodeKeyToPemForm(Key key) {
        return "-----BEGIN " +
                (key instanceof PrivateKey ? "PRIVATE" : "PUBLIC") +
                " KEY-----\n" +
                Base64.getEncoder().encodeToString(key.getEncoded()) +
                "\n-----END " +
                (key instanceof PrivateKey ? "PRIVATE" : "PUBLIC") +
                " KEY-----\n";
    }
}
