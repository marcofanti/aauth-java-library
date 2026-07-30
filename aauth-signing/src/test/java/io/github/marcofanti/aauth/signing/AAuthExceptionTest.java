package io.github.marcofanti.aauth.signing;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;

class AAuthExceptionTest {

    @Test
    void baseExceptionDefaultsToNoCodeAndEmptyDetails() {
        AAuthException e = new AAuthException("boom");

        assertThat(e.getMessage()).isEqualTo("boom");
        assertThat(e.errorCode()).isNull();
        assertThat(e.details()).isEmpty();
    }

    @Test
    void baseExceptionPreservesCause() {
        IllegalStateException cause = new IllegalStateException("root");
        AAuthException e = new AAuthException("wrapped", cause);

        assertThat(e.getCause()).isSameAs(cause);
    }

    @Test
    void signatureExceptionDefaultsToInvalidSignatureCode() {
        HttpSignatureException e = new HttpSignatureException("bad signature");

        assertThat(e.errorCode()).isEqualTo(HttpSignatureException.ERROR_INVALID_SIGNATURE);
        assertThat(e.details()).isEmpty();
    }

    @Test
    void signatureExceptionCarriesCodeDetailsAndCause() {
        IllegalArgumentException cause = new IllegalArgumentException("parse");
        HttpSignatureException e =
                new HttpSignatureException("bad", "unsupported_algorithm", Map.of("scheme", "hwk"), cause);

        assertThat(e.errorCode()).isEqualTo("unsupported_algorithm");
        assertThat(e.details()).containsEntry("scheme", "hwk");
        assertThat(e.getCause()).isSameAs(cause);
    }

    @Test
    void signatureExceptionWithCauseOnlyKeepsDefaultCode() {
        HttpSignatureException e = new HttpSignatureException("bad", new IllegalStateException("x"));

        assertThat(e.errorCode()).isEqualTo(HttpSignatureException.ERROR_INVALID_SIGNATURE);
    }
}
