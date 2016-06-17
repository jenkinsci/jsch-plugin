package org.jenkinsci.plugins.jsch;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHAuthenticator;
import com.cloudbees.jenkins.plugins.sshcredentials.SSHAuthenticatorException;
import com.cloudbees.jenkins.plugins.sshcredentials.SSHAuthenticatorFactory;
import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.cloudbees.plugins.credentials.common.StandardUsernameCredentials;
import com.jcraft.jsch.JSchException;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.util.Secret;

import java.io.UnsupportedEncodingException;
import java.util.logging.Logger;

/**
 * @author stephenc
 * @since 25/10/2012 14:49
 */
public class JSchSSHPublicKeyAuthenticator extends SSHAuthenticator<JSchConnector, SSHUserPrivateKey> {

    /**
     * Our logger.
     */
    private static final Logger LOGGER = Logger.getLogger(JSchSSHPublicKeyAuthenticator.class.getName());

    /**
     * Constructor.
     *
     * @param connector the connection we will be authenticating.
     */
    public JSchSSHPublicKeyAuthenticator(JSchConnector connector, SSHUserPrivateKey user) {
        this(connector, user, null);
    }

    /**
     * Constructor.
     *
     * @param connector the connection we will be authenticating.
     * @since 1.4
     */
    public JSchSSHPublicKeyAuthenticator(@NonNull JSchConnector connector, @NonNull SSHUserPrivateKey user,
                                         @CheckForNull String username) {
        super(connector, user, username);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean canAuthenticate() {
        return !getConnection().hasSession()
                || (getConnection().getSession().isConnected() && getConnection().getSession().getUserInfo() == null);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected boolean doAuthenticate() {
        try {
            final SSHUserPrivateKey user = getUser();
            final Secret userPassphrase = user.getPassphrase();
            final String passphrase = userPassphrase == null ? null : userPassphrase.getPlainText();
            byte[] passphraseBytes = passphrase == null ? null : passphrase.getBytes("UTF-8");
            for (String privateKey : getPrivateKeys(user)) {
                getConnection().getJSch().addIdentity(getUsername(), privateKey.getBytes("UTF-8"), null,
                        passphraseBytes);
            }

            return true;
        } catch (JSchException e) {
            e.printStackTrace(getListener().error("Failed to authenticate with public key"));
            return false;
        } catch (UnsupportedEncodingException e) {
            throw new SSHAuthenticatorException(e);
        }
    }

    @NonNull
    @Override
    public Mode getAuthenticationMode() {
        return Mode.BEFORE_CONNECT;
    }

    /**
     * {@inheritDoc}
     */
    @Extension
    public static class Factory extends SSHAuthenticatorFactory {

        /**
         * {@inheritDoc}
         */
        @Override
        @SuppressWarnings("unchecked")
        protected <C, U extends StandardUsernameCredentials> SSHAuthenticator<C, U> newInstance(@NonNull C session,
                                                                                                @NonNull U user) {
            return newInstance(session, user, null);
        }

        /**
         * {@inheritDoc}
         */
        @Nullable
        @Override
        @SuppressWarnings("unchecked")
        protected <C, U extends StandardUsernameCredentials> SSHAuthenticator<C, U> newInstance(@NonNull C session,
                                                                                                @NonNull U user,
                                                                                                @CheckForNull String
                                                                                                        username) {
            if (supports(session.getClass(), user.getClass())) {
                return (SSHAuthenticator<C, U>) new JSchSSHPublicKeyAuthenticator((JSchConnector) session,
                        (SSHUserPrivateKey) user, username);
            }
            return null;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        protected <C, U extends StandardUsernameCredentials> boolean supports(@NonNull Class<C> connectionClass,
                                                                              @NonNull Class<U> userClass) {
            return JSchConnector.class.isAssignableFrom(connectionClass)
                    && SSHUserPrivateKey.class.isAssignableFrom(userClass);
        }

        private static final long serialVersionUID = 1L;
    }
}
