package com.goeswhere.sshkeycapture;

import org.apache.sshd.common.keyprovider.AbstractKeyPairProvider;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.server.SshServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.*;

public class KeyCapture {
    public static final Session.AttributeKey<String> ACCOUNT_NAME = new Session.AttributeKey<>();
    public static final Session.AttributeKey<Boolean> JUST_ADDED = new Session.AttributeKey<>();
    private static final Logger logger = LoggerFactory.getLogger(KeyCapture.class);


    public static void main(String[] args) throws IOException, InterruptedException {
        SshServer sshd = SshServer.setUpDefaultServer();

        final KeyPair serverKeyPair = serverKeyPair();
        final Map<String, String> userDatabase = new HashMap<>();
        final Map<String, String> issuedTokens = new HashMap<>();

        sshd.setPort(9422);

        sshd.setPublickeyAuthenticator((username, key, session) -> {
            final String newUser = issuedTokens.get(username);
            if (null != newUser) {
                userDatabase.put(newUser, fingerprint(key));
                session.setAttribute(JUST_ADDED, true);
                session.setAttribute(ACCOUNT_NAME, username);
                return true;
            }

            final String expectedKey = userDatabase.get(username);
            final String fingerprint = fingerprint(key);

            logger.info("{} trying to authenticate with {}, db contains {}", username, fingerprint, expectedKey);

            if (null == expectedKey || !expectedKey.equals(fingerprint)) {
                return false;
            }

            session.setAttribute(ACCOUNT_NAME, username);
            session.setAttribute(JUST_ADDED, false);
            return true;
        });

        sshd.setKeyPairProvider(new AbstractKeyPairProvider() {
            @Override
            public Iterable<KeyPair> loadKeys() {
                return Collections.singleton(serverKeyPair);
            }
        });

        sshd.setShellFactory(CommandWrapper.wrap((in, out, err, session) -> {
            try (final PrintStream ps = new PrintStream(out)) {
                final String whom = session.getAttribute(ACCOUNT_NAME);

                if (session.getAttribute(JUST_ADDED)) {
                    ps.println("Added successfully!  You can now log-in normally.\r");
                    issuedTokens.remove(whom);
                    return 0;
                }
                ps.println("Hi!  You've successfully authenticated as " + whom + "\r");
                ps.println("Bye!\r");
            }
            return 0;
        }));

        sshd.start();

            try (final BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
                while (true) {
                    System.out.print("Enter a new user name, or blank to exit: ");
                    final String user = stdin.readLine().trim();
                    if (user.isEmpty()) {
                        return;
                    }

                    final String newUuid = UUID.randomUUID().toString();
                    issuedTokens.put(newUuid, user);

                    System.out.println("Ask '" + user + "' to ssh to '" + newUuid + "@...'");
                }
        }
    }

    private static KeyPair serverKeyPair() {
        try {
            return SecurityUtils.getKeyPairGenerator("RSA").generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("couldn't generate a key", e);
        }
    }

    public static String fingerprint(PublicKey key) {
        return key.getAlgorithm() + " " + Base64.getEncoder().encodeToString(key.getEncoded());
    }

}
