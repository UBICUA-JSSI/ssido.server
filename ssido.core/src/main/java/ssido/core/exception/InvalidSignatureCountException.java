package ssido.core.exception;

import ssido.core.data.ByteArray;

public final class InvalidSignatureCountException extends AssertionFailedException {
    private final ByteArray credentialId;
    private final long expectedMinimum;
    private final long received;

    public InvalidSignatureCountException(ByteArray credentialId, long expectedMinimum, long received) {
        super(String.format("Signature counter must increase. Expected minimum: %s, received value: %s", expectedMinimum, received));
        this.credentialId = credentialId;
        this.expectedMinimum = expectedMinimum;
        this.received = received;
    }

    public ByteArray getCredentialId() {
        return this.credentialId;
    }

    public long getExpectedMinimum() {
        return this.expectedMinimum;
    }

    public long getReceived() {
        return this.received;
    }

    protected boolean canEqual(final java.lang.Object other) {
        return other instanceof InvalidSignatureCountException;
    }
}
