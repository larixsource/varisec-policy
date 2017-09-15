package cl.larix.varisec;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolver;

import java.security.Key;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

class VariJWTUtil {
    static VariJWTClaims parse(String token) {
        final VariJWTClaims variClaims = new VariJWTClaims();

        SigningKeyResolver keyResolver = new SigningKeyResolver() {
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
