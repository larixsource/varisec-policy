package cl.larix.varisec;

import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

class VariJWTClaims {
    private String idpUserId;
    private Integer userId;
    private Set<Integer> organizations = new HashSet<>();
    private Set<String> roles = new HashSet<>();

    Optional<String> getIdpUserId() {
        if (idpUserId == null) {
            return Optional.empty();
        } else {
            return Optional.of(idpUserId);
        }
    }

    void setIdpUserId(String idpUserId) {
        this.idpUserId = idpUserId;
    }

    Optional<Integer> getUserId() {
        if (userId == null) {
            return Optional.empty();
        } else {
            return Optional.of(userId);
        }
    }

    void setUserId(Integer userId) {
        this.userId = userId;
    }

    Set<Integer> getOrganizations() {
        return organizations;
    }

    void addOrganizations(Collection<Integer> organizations) {
        this.organizations.addAll(organizations);
    }

    Set<String> getRoles() {
        return roles;
    }

    void addRoles(Collection<String> roles) {
        this.roles.addAll(roles);
    }
}
