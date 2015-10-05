package com.goeswhere.sshkeycapture;

import org.apache.sshd.common.keyprovider.AbstractKeyPairProvider;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.UserAuth;
import org.apache.sshd.server.auth.UserAuthKeyboardInteractive;
import org.apache.sshd.server.auth.UserAuthKeyboardInteractiveFactory;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.concurrent.GuardedBy;
import java.io.IOException;
import java.io.PrintStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.*;
import java.util.stream.Collectors;

public class KeyCapture implements AutoCloseable {
    private static final Logger logger = LoggerFactory.getLogger(KeyCapture.class);

    static final Session.AttributeKey<String> ACCOUNT_NAME = new Session.AttributeKey<>();
    static final Session.AttributeKey<List<String>> COLLECTED_KEYS = new Session.AttributeKey<>();
    static final Session.AttributeKey<Boolean> JUST_ADDED = new Session.AttributeKey<>();

    private final SshServer sshd = SshServer.setUpDefaultServer();
    private final KeyPair serverKeyPair = serverKeyPair();

    @GuardedBy("this")
    private final Map<String, String> userDatabase = new HashMap<>();
    @GuardedBy("this")
    private final Map<String, String> issuedTokens = new HashMap<>();

    public KeyCapture() {
        sshd.setPort(9422);

        sshd.setPublickeyAuthenticator((username, key, session) -> {
            final String expectedKey;
            final String fingerprint = fingerprint(key);

            synchronized (KeyCapture.this) {
                final String newUser = issuedTokens.get(username);
                if (null != newUser) {
                    List<String> collectedKeys = session.getAttribute(COLLECTED_KEYS);
                    if (null == collectedKeys) {
                        session.setAttribute(COLLECTED_KEYS, collectedKeys = new ArrayList<>());
                    }

                    collectedKeys.add(fingerprint);
                    return false;
                }

                expectedKey = userDatabase.get(username);
            }

            logger.info("{} trying to authenticate with {}, db contains {}", username, fingerprint, expectedKey);

            if (null == expectedKey || !expectedKey.equals(fingerprint)) {
                return false;
            }

            session.setAttribute(ACCOUNT_NAME, username);
            session.setAttribute(JUST_ADDED, false);
            return true;
        });

        sshd.setUserAuthFactories(Arrays.asList(
                sshd.DEFAULT_USER_AUTH_PUBLIC_KEY_FACTORY,
                new UserAuthKeyboardInteractiveFactory() {
                    @Override
                    public UserAuth create() {
                        return new AskAboutTheKeysInteractively();
                    }
                }));


        sshd.setKeyPairProvider(new AbstractKeyPairProvider() {
            @Override
            public Iterable<KeyPair> loadKeys() {
                return Collections.singleton(serverKeyPair);
            }
        });

        sshd.setShellFactory(CommandWrapper.wrap((in, out, err, session) -> {
            try (final PrintStream ps = new PrintStream(out)) {
                final String whom = session.getAttribute(ACCOUNT_NAME);

                if (session.getAttribute(JUST_ADDED) == Boolean.TRUE) {
                    ps.println("Added successfully!  You can now log-in normally.\r");
                    synchronized (KeyCapture.this) {
                        issuedTokens.remove(whom);
                    }
                    return 0;
                }
                ps.println("Hi!  You've successfully authenticated as " + whom + "\r");
                ps.println("Bye!\r");
            }
            return 0;
        }));
    }

    public void start() throws IOException {
        sshd.start();
    }

    public void close() throws IOException {
        sshd.close();
    }

    private static KeyPair serverKeyPair() {
        try {
            return SecurityUtils.getKeyPairGenerator("RSA").generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("couldn't generate a key", e);
        }
    }

    static String fingerprint(PublicKey key) {
        return key.getAlgorithm() + " " + Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public synchronized String newTokenFor(String user) {
        final String newUuid = UUID.randomUUID().toString();
        issuedTokens.put(newUuid, user);
        return newUuid;
    }

    public Map<String, String> getUsers() {
        return Collections.unmodifiableMap(userDatabase);
    }

    private static class AskAboutTheKeysInteractively extends UserAuthKeyboardInteractive {
        @Override
        protected boolean isInteractionPromptEchoEnabled() {
            return true;
        }

        @Override
        protected String getInteractionInstruction() {
            List<String> collectedKeys = session.getAttribute(COLLECTED_KEYS);
            if (null == collectedKeys || collectedKeys.isEmpty()) {
                return "You didn't provide any keys!  You must, you must.";
            }

            StringBuilder keyList = new StringBuilder("Pick some keys: \n");
            for (int i = 0; i < collectedKeys.size(); i++) {
                keyList.append(i+1).append(") ").append(collectedKeys.get(i)).append("\n");
            }

            return keyList.toString();
        }

        @Override
        protected String getInteractionPrompt() {
            List<String> collectedKeys = session.getAttribute(COLLECTED_KEYS);
            if (null == collectedKeys || collectedKeys.isEmpty()) {
                return "Please reconnect and try again; press anything to exit.";
            }

            return "Your choice (e.g. '1 2'): ";
        }

        @Override
        protected boolean checkPassword(ServerSession session, String username, String password) throws Exception {
            try {
                final List<Integer> selections = Arrays.asList(password.split("\\s+")).stream()
                        .map(Integer::parseInt)
                        .collect(Collectors.toList());
                List<String> collectedKeys = session.getAttribute(COLLECTED_KEYS);
                System.out.println("keys to use:");
                selections.forEach(idx -> System.out.println(collectedKeys.get(idx - 1)));
                return true;
            } catch (NumberFormatException e) {
                logger.info("couldn't parse " + password, e);
                return false;
            }
        }
    }

}
