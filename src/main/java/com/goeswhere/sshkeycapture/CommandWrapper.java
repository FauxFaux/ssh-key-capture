package com.goeswhere.sshkeycapture;

import com.sun.corba.se.spi.activation.Server;
import org.apache.sshd.common.Factory;
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
import java.util.function.Supplier;

public abstract class CommandWrapper implements Command, SessionAware {
    private static final Logger logger = LoggerFactory.getLogger(CommandWrapper.class);

    private ExitCallback callback;
    private InputStream in;
    private OutputStream out;
    private OutputStream err;
    protected ServerSession session;

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

    @FunctionalInterface
    public interface CommandRunner {
        int run(InputStream in, OutputStream out, OutputStream err, ServerSession session) throws IOException;
    }

    public static Factory<Command> wrap(CommandRunner runner) {
        return () -> new CommandWrapper() {
            @Override
            public int run(InputStream in, OutputStream out, OutputStream err) throws IOException {
                return runner.run(in, out, err, session);
            }
        };
    }

    public abstract int run(InputStream in, OutputStream out, OutputStream err) throws IOException;

    @Override
    public void setSession(ServerSession session) {
        this.session = session;
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
