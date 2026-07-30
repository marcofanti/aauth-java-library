package io.github.marcofanti.aauth.signing;

import java.util.Map;

/**
 * Key discovery callback used by signature and token verification.
 *
 * <p>For the {@code jwks_uri} scheme the implementation SHOULD perform two-step discovery: fetch
 * {@code {id}/.well-known/{dwk}}, extract {@code jwks_uri}, fetch the JWKS, and return the full
 * JWKS document. For the {@code jwt} scheme it is called with the JWT's {@code iss}, {@code dwk}
 * and header {@code kid}. Implementations may ignore arguments they don't need.
 */
@FunctionalInterface
public interface JwksFetcher {

    /**
     * Fetches the JWKS document for a signer.
     *
     * @param id the signer identifier (HTTPS URL)
     * @param dwk the well-known metadata document name (may be {@code null})
     * @param kid the key identifier being looked up (may be {@code null})
     * @return the JWKS document ({@code {"keys": [...]}}) or {@code null} when unavailable
     */
    Map<String, Object> fetch(String id, String dwk, String kid);
}
