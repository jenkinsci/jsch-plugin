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
import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import com.cloudbees.plugins.credentials.CredentialsScope;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.util.Secret;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.pubkey.UserAuthPublicKeyFactory;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class JSchSSHPublicKeyAuthenticatorTest {

    private final KeyPairProvider keyPairProvider = new SimpleGeneratorHostKeyProvider();
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
        user = new SSHUserPrivateKey() {

            @NonNull
            public String getUsername() {
                return "foobar";
            }

            @NonNull
            public String getDescription() {
                return "";
            }

            @NonNull
            public String getId() {
                return "";
            }

            public CredentialsScope getScope() {
                return CredentialsScope.SYSTEM;
            }

            @NonNull
            public CredentialsDescriptor getDescriptor() {
                return new CredentialsDescriptor() {
                    @Override
                    public String getDisplayName() {
                        return "";
                    }
                };
            }

            @NonNull
            public String getPrivateKey() {
                // just want a valid key... I generated this and have thrown it away (other than here)
                // do not use other than in this test
                // this is a 4096-bit RSA key generated via:
                // openssl genrsa 4096
                return "-----BEGIN RSA PRIVATE KEY-----\n" +
                        "MIIJKwIBAAKCAgEA4CmW6yE6HT8eTIsoN71tAn5EEfLqEDK2TzIT7wq8+lQB3CIx\n" +
                        "9adUsgepILVUPc1miioTE1ujmVqjIqkeU6RJ6OuYH1+8AQXSUuq3fm3Zee023J7d\n" +
                        "O52ktTCtTZmypqY72DNKBpfKYwat6CPtzcv2s8yRWqJXpuSIZaSgpkH/26XNOyj0\n" +
                        "UCuOY5Z6t707sXuAtq1yg9SseCnbwbMuyUX8I9qH7d93LWmSGpzR6lrOlUg1ndg9\n" +
                        "AlmBS2A0xdnIt6EVOa+2OipT7/6q69a2GG+GUtld59NXkEpQJksDYW8apwgty7nr\n" +
                        "DSpc4AI52uOFoVIH+tYFvUPm2I78sg8v4vb5JkK5f3Kwb82EwWQZNWDvcRRoYDzv\n" +
                        "U6CIaM6An6EjxyPjfkLaB/2qkoRTi5Zh7BVbEHLyc9lkxNZ32UnZeLNwOm6JVBdf\n" +
                        "2AMOcgmVRAQFUfr9pnuE9Ndzx1PVeRd/myZ+fp1rxRF9W7sE9scvVsLh0Z9WcHa8\n" +
                        "rRZulCKrtnHG6oQVP3pf7MrkjQXRY8CNm9oeWqmTxVi/oL1Ji0/Aty5BHerHtoCY\n" +
                        "FN9mSR2cmY+ZMwGmtbv3is5xdUq1o4pco5a6vrtVDst4wQIuaRpz7/3YU26Rr16r\n" +
                        "sPCqaARPGXKLHJ/COMydffccgvixRf9gUI+NVvs2Wh+2VwfQ3KkX4Fmdk+0CAwEA\n" +
                        "AQKCAgEAxc4NXckBRiOXcgXt5FnkYqnXGVuYjdiiJXpUOsDoB6GvznfiTBpvU3YN\n" +
                        "GU7JWovw6wS7tn5L/BwODpzbpQU5Ly8OGslY1jIz6XUznH4ExWG84qvRHzU5zaV5\n" +
                        "mBuDmSjhcCO6M90n+4A+X7Wst8g/F2Px89+Dp0LM1ZyTIoLk6wcA9i5qgIAe8uQr\n" +
                        "wA1dKn2IFCsz/P7jflm5kNCz/WojV+QTxKVHviwFgDRXzAx7dSG2JmZVV8hxnnjz\n" +
                        "uI84Xknnt/LEw8jsLsA0RU4/e4qWJm+nPNWy1CGvXksdXZI0G6bM+pRBxWlXcVil\n" +
                        "gvD4z2Tao87OW7gacYijleBu6kHzkdfLisuC8WyEfUWAtUAb2qHKQAf0HYvuiJ5O\n" +
                        "OAORp6oxxtQzGHVcYLh68lrVE39dD80OKN7OltuPRp4lllUZtGzlBdPfBiRQiSPN\n" +
                        "x6SmuSxGpqhJz96S2NT6ZVBBIuYuVXX6KhUdzB/45TzqBCXfwHJsv/DoRmcptKJx\n" +
                        "kzSMTHZ9orLB9bthjMTsKmQUduPafqo1AspB0jxcKShias+D4DcymIbXpHEZ0TQZ\n" +
                        "VjcPMzH4DTnoIaGkyVLg49hEb2ogH9RmM/Hsx7aZA00Aqn/BMDWhkMgHJRActKLC\n" +
                        "SB0amuNCEu55+bHe5ejB+BhcMhlemtBxliqsfEy52JVwOBTX5sUCggEBAPI9p64n\n" +
                        "J3tUTsuVWq46SgTJcpqY5GbNPg+f6qHtZgWyoAkAVRgYu7OXLFbcTtBA0axo0pm7\n" +
                        "3kQCXDEAznHeGAENtodoVHzbvKTmBUJ0WbBqNiJFx8R4u3RB1K4BW5uDo5QTb/aQ\n" +
                        "CDQ2yF5J60ltdskyfDUahkW2wPJEUnslyeViGgVrP21u0EhC18NpghWUQsN1RQdW\n" +
                        "e+h0ds15armLMGxxf62ZI5GZl+RLwwjIczjxGm00C++yekasGWnkDikx50UGthyR\n" +
                        "k4zG/a2ctt00hhgbHafQGwJj3VhTTPZvaqfdcHZYUH1B9S5ZsBHsiadON8w7z2mB\n" +
                        "aAK/ktrUxe+C7AMCggEBAOzlEAxmfAyg7AUbN516DG1cZ5xX3vWc4s7jy6GsaD7d\n" +
                        "5OEgZQQVZmi1xcjZaiF/BKOnzFDr/RlQJhNFsT4qotfk5Y79PMed/eoOg7DqdxAa\n" +
                        "w1uzlqhrDHnlBXAXY5De7L3su4rBMg2O570L5FUbffPgym4aXaxg/etVUV7pQqPV\n" +
                        "lcuyxBp93lG6MnHTJ4CZ7gTwb+XyFfhdF6P9WZOwpdoCjQg2eoYMZBo5h7LivziY\n" +
                        "7N6hKgm5EQ2mrfJqHB3H540Dy4P03LEjk5xQDUnBn/gpj4ZePBFaiueEvlOXiCwP\n" +
                        "+jXIfF+kAlef/UEBOJUHzzp39elqkU0msKLxghLzlU8CggEBAOrcBBrBM3JLRyny\n" +
                        "4DxTnzgM5+QjoC5bh3Q2o5HjTSrxCGAxxk7ajAGO7Bo69t7KOX9jEeyjTNe7Qg7w\n" +
                        "rTeREMzUsseNy3xSvw9RRIAttldoYpvP8+L0+ym4Oa+K+XpJousJ/V+cPZgCFTn1\n" +
                        "iP1j9+sR24LQ+KXWjjNVMnLbLGgNORVP6er7qUymIfL/9HNfj2tZ41c97lxtrlGB\n" +
                        "Coxh+szpLdTtyKJ9u9pH6gw17CClAe4mq/v1mr+yU+FqjqA6FfPCkgYYzmmK9KDC\n" +
                        "dDj7l5b/kz0Ec2tZz1y3RsMXOt0NwN+8uCz5KfGKWz7FiqB/IXIN+wZbxLAFdShd\n" +
                        "aprQ4GkCggEBAIOKokGwertsdAJV3aj1B4eGYwYeiPCrgAnP1dfdazlVb21O1qjQ\n" +
                        "1T/Zh40CpPsak9HoL/zTPYRby/ixnzzc4fWt5YZjuedCJKdeDeQkHZ70rXvzGfpF\n" +
                        "DvV0pXNbmW7tSlof5PekVY3Px4Bi5RQZIvRT4zQGMfOxG+4cPwXL0rQ0umwUxO3M\n" +
                        "7LFHChHIZUv0rYVSmV/+8BIsZx8pZB8tXLrU5ckkrx5WLROe1GoRnIrp58WrijNB\n" +
                        "72U8I6TTJO+ofDwCWnTYd99o2ONYVDibap+bPFYpZ4NfWng6bpDuOK/240IQJHfb\n" +
                        "E23iqfb5nZircHeP+x30jeBgVn70Sf0KAuMCggEBAOG5wh1m5H981ZY1EPFxYpvH\n" +
                        "mh2K0eoNUGlSmWcuq+L1k93xG5bsaKpZH2xSpRqcwARvAy+0kIncE14QAVsBuse9\n" +
                        "B4G86IUlsKYe2aZt3Zo+2bz+CdHWZHYcNyj+aYrzRwB/z3d3F5sYccPL/Tmu34KQ\n" +
                        "tU4Cglzfz8lGzpIwM7HN2JyubjO0Iy1UbEqP0RqK38LYP0SYPoinXVKXKAwEZ7gp\n" +
                        "23bCUz4li9GjJ/Ke7ztcFES/9HzyUTw/L7VS6LHf99W0yjHpZ2OaqxrSXHGSXP0R\n" +
                        "GNuyG1OI+KmyNhb332Bm3R8mSM3mw9wBrFM1VUmBtNwjn1P8qnyEwzo9tdZNxoI=\n" +
                        "-----END RSA PRIVATE KEY-----";
            }

            @CheckForNull
            public Secret getPassphrase() {
                return null;
            }

            @NonNull
            public List<String> getPrivateKeys() {
                return Collections.singletonList(getPrivateKey());
            }
        };
    }

    @Test
    public void testAuthenticate() throws Exception {
        SshServer sshd = SshServer.setUpDefaultServer();
        sshd.setPort(0);
        sshd.setKeyPairProvider(keyPairProvider);
        sshd.setPublickeyAuthenticator((username, key, session) -> username.equals("foobar"));
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
        sshd.setKeyPairProvider(keyPairProvider);
        sshd.setPublickeyAuthenticator((username, key, session) -> username.equals("foobar"));
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
}
