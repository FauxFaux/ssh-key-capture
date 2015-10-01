package com.goeswhere.sshkeycapture;

import org.apache.sshd.server.Command;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.SessionAware;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public abstract class CommandWrapper implements Command, SessionAware {
    private static final Logger logger = LoggerFactory.getLogger(CommandWrapper.class);

    private ExitCallback callback;
    private InputStream in;
    private OutputStream out;
    private OutputStream err;
    private String user;
    private boolean justAdded;

    @Override
    public void start(Environment env) throws IOException {
        new Thread("command-wrapper") {
            @Override
            public void run() {
                int code = 0;
                try {
                    code = CommandWrapper.this.run(in, out, err);
                } catch (Exception e) {
                    code = 1;
                    logger.error("command failed", e);
                } finally {
                    closeQuietly(out, err);
                    callback.onExit(code);
                }
            }
        }.start();
    }

    public abstract int run(InputStream in, OutputStream out, OutputStream err) throws IOException;

    @Override
    public void setSession(ServerSession session) {
        this.user = session.getAttribute(KeyCapture.ACCOUNT_NAME);
        this.justAdded =  session.getAttribute(KeyCapture.JUST_ADDED);
    }

    @Override
    public void setOutputStream(OutputStream out) {
        this.out = out;
    }

    @Override
    public void setInputStream(InputStream in) {
        this.in = in;
    }

    @Override
    public void setExitCallback(ExitCallback callback) {
        this.callback = callback;
    }

    @Override
    public void setErrorStream(OutputStream err) {
        this.err = err;
    }

    @Override
    public void destroy() {
    }

    protected String getUser() {
        return user;
    }

    protected boolean justAdded() {
        return justAdded;
    }

    private static void closeQuietly(OutputStream... streams) {
        for (OutputStream o : streams) {
            try {
                o.flush();
                o.close();
            } catch (IOException e) {
                logger.debug("couldn't close stream", e);
            }
        }
    }
}