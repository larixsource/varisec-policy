package cl.larix.varisec;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolver;

import java.security.Key;
import java.util.*;

/**
 * Vari JWT claims.
 *
 * @author Jorge Riquelme (jorge@larix.cl)
 */
class VariJWTClaims {
    private String idpUserId;
    private Integer userId;
    private Set<Integer> organizations = new HashSet<>();
    private Set<String> roles = new HashSet<>();

    /**
     * Returns the sub claim.
     *
     * @return KeyCloak user id.
     */
    Optional<String> getIdpUserId() {
        if (idpUserId == null) {
            return Optional.empty();
        } else {
            return Optional.of(idpUserId);
        }
    }

    private void setIdpUserId(String idpUserId) {
        this.idpUserId = idpUserId;
    }

    /**
     * Returns the vari_user_id claim.
     *
     * @return Vari user id.
     */
    Optional<Integer> getUserId() {
        if (userId == null) {
            return Optional.empty();
        } else {
            return Optional.of(userId);
        }
    }

    private void setUserId(Integer userId) {
        this.userId = userId;
    }

    /**
     * Returns the vari_organization_id claim.
     *
     * @return Vari organization id list.
     */
    Set<Integer> getOrganizations() {
        return organizations;
    }

    private void addOrganizations(Collection<Integer> organizations) {
        this.organizations.addAll(organizations);
    }

    /**
     * Returns the real_access.roles claim.
     *
     * @return KeyCloak realm roles list (which includes Vari roles).
     */
    Set<String> getRoles() {
        return roles;
    }

    private void addRoles(Collection<String> roles) {
        this.roles.addAll(roles);
    }

    /**
     * Parses a JWT token and extract the claims used by Vari (sub, vari_user_id, vari_organization_id and
     * realm_access.roles). This method trusts that the token is valid at this point (we use a KeyCloak Oauth policy
     * before this one in all our API).
     *
     * @param token JWT token.
     * @return Vari claims.
     */
    static VariJWTClaims parse(String token) {
        final VariJWTClaims variClaims = new VariJWTClaims();

        SigningKeyResolver keyResolver = new SigningKeyResolver() {
            @SuppressWarnings("unchecked")
            @Override
            public Key resolveSigningKey(JwsHeader jwsHeader, Claims claims) {
                try {
                    variClaims.setIdpUserId(claims.getSubject());
                    variClaims.setUserId(claims.get("vari_user_id", Integer.class));

                    List<Integer> orgs = claims.get("vari_organization_id", ArrayList.class);
                    if (orgs != null) {
                        variClaims.addOrganizations(orgs);
                    }

                    HashMap realmAccess = claims.get("realm_access", HashMap.class);
                    if (realmAccess != null) {
                        List<String> roles = (ArrayList) realmAccess.get("roles");
                        if (roles != null) {
                            variClaims.addRoles(roles);
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                return null;
            }

            @Override
            public Key resolveSigningKey(JwsHeader jwsHeader, String s) {
                return null;
            }
        };
        try {
            Jwts.parser().setSigningKeyResolver(keyResolver).parseClaimsJws(token).getBody();
        } catch (Exception e) {
            // we trust that the token is valid at this point.
        }
        return variClaims;
    }
}
