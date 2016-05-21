package com.cisco.clique.sdk.exceptions;

public class UntrustedIdentityException extends Exception {

    public UntrustedIdentityException() {
        super();
    }

    public UntrustedIdentityException(String message) {
        super(message);
    }

    public UntrustedIdentityException(String message, Throwable cause) {
        super(message, cause);
    }

    public UntrustedIdentityException(Throwable cause) {
        super(cause);
    }

    protected UntrustedIdentityException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
