package com.goeswhere.sshkeycapture;

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.keyprovider.AbstractKeyPairProvider;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.SshServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.CountDownLatch;

public class KeyCapture {
    public static final Session.AttributeKey<String> ACCOUNT_NAME = new Session.AttributeKey<>();
    public static final Session.AttributeKey<Boolean> JUST_ADDED = new Session.AttributeKey<>();
    private static final Logger logger = LoggerFactory.getLogger(KeyCapture.class);


    public static void main(String[] args) throws IOException, InterruptedException {
        SshServer sshd = SshServer.setUpDefaultServer();
        final CountDownLatch readyToShutdown = new CountDownLatch(1);

        final KeyPair serverKeyPair = serverKeyPair();
        final Map<String, String> userDatabase = new HashMap<>();

        final String adminKey = UUID.randomUUID().toString();
        System.out.println(adminKey);

        sshd.setPort(9422);

        sshd.setPublickeyAuthenticator((username, key, session) -> {
            if (username.startsWith(adminKey)) {
                final String newUser = username.substring(adminKey.length() + 1);
                userDatabase.put(newUser, fingerprint(key));
                session.setAttribute(JUST_ADDED, true);
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

        sshd.setShellFactory(() -> new CommandWrapper() {
            @Override
            public int run(InputStream in, OutputStream out, OutputStream err) throws IOException {
                try (final PrintStream ps = new PrintStream(out)) {
                    if (justAdded()) {
                        ps.println("Added successfully!  You can now log-in normally.\r");
                        return 0;
                    }
                    ps.println("Hi!  You've successfully authenticated as " + getUser() + "\r");
                    ps.println("Bye!\r");
                }
                return 0;
            }
        });

        sshd.start();
        readyToShutdown.await();
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
