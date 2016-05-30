package com.cisco.clique.sdk.validation;

public class InvalidBlockException extends Exception {
    public InvalidBlockException() {
        super();
    }

    public InvalidBlockException(String message) {
        super(message);
    }

    public InvalidBlockException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidBlockException(Throwable cause) {
        super(cause);
    }

    protected InvalidBlockException(
            String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
