package com.goeswhere.sshkeycapture;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

public class SampleApp {
    public static void main(String[] args) throws IOException {

        try (final KeyCapture keyCapture = new KeyCapture();
             final BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {

            keyCapture.start();

            while (true) {
                System.out.print("Enter a new user name, or blank to exit: ");
                final String user = trimAndCoalesce(stdin.readLine());
                if (user.isEmpty()) {
                    printCapturedUsers(keyCapture);
                    return;
                }

                final String newUuid = keyCapture.newTokenFor(user);

                System.out.println("Ask '" + user + "' to ssh to '" + newUuid + "@...'");
            }
        }
    }

    private static String trimAndCoalesce(String line) {
        if (null == line) {
            return "";
        }
        return line.trim();
    }

    private static void printCapturedUsers(KeyCapture keyCapture) {
        System.out.println("captured users:");
        keyCapture.getUsers().forEach((name, key) -> {
            System.out.println(name + ": " + key);
        });
    }
}