package cl.larix.varisec;

import io.apiman.gateway.engine.beans.ApiRequest;
import io.apiman.gateway.engine.beans.ApiResponse;
import io.apiman.gateway.engine.beans.PolicyFailure;
import io.apiman.gateway.engine.beans.PolicyFailureType;
import io.apiman.gateway.engine.beans.exceptions.ConfigurationParseException;
import io.apiman.gateway.engine.components.IPolicyFailureFactoryComponent;
import io.apiman.gateway.engine.policy.IPolicy;
import io.apiman.gateway.engine.policy.IPolicyChain;
import io.apiman.gateway.engine.policy.IPolicyContext;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Vari Security Policy.
 *
 * @author Jorge Riquelme (jorge@larix.cl)
 */
public class SecurityPolicy implements IPolicy {
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String ACCESS_TOKEN_QUERY_KEY = "access_token";
    private static final String BEARER = "bearer ";

    private static final int HTTP_BAD_REQUEST = 400;
    private static final int HTTP_UNAUTHORIZED = 401;

    private static final int AUTH_NOT_PROVIDED = 12005;
    private static final int MISSING_CLAIM = 12009;
    private static final int BAD_ORGANIZATION_PARAMETER = 12009;
    private static final int UNKNOWN_ORGANIZATION = 12009;

    private static final String VARI_USER_ID_HEADER = "X-Vari-UserId";
    private static final String VARI_IDPUSER_ID_HEADER = "X-Vari-IDPUserId";
    private static final String VARI_ROLES_HEADER = "X-Vari-Roles";
    private static final String VARI_ORGANIZATIONS_HEADER = "X-Vari-Organizations";
    private static final String ORG_QUERY_PARAM = "org";

    public SecurityPolicy() {
    }

    @Override
    public Object parseConfiguration(String jsonConfiguration) throws ConfigurationParseException {
        return null;
    }

    @Override
    public void apply(ApiRequest request, IPolicyContext context, Object config,
                      IPolicyChain<ApiRequest> chain) {
        // get token from Authorization header
        String jwt = Optional.ofNullable(request.getHeaders().get(AUTHORIZATION_HEADER))
                // If seems to be bearer token
                .filter(e -> e.toLowerCase().startsWith(BEARER))
                // Get out token value
                .map(e -> e.substring(BEARER.length(), e.length()))
                // Otherwise attempt to get from the access_token query param
                .orElse(request.getQueryParams().get(ACCESS_TOKEN_QUERY_KEY));
        if (jwt == null) {
            PolicyFailure pf = getFailureFactory(context).createFailure(PolicyFailureType.Authentication,
                    AUTH_NOT_PROVIDED, "");
            pf.setResponseCode(HTTP_UNAUTHORIZED);
            chain.doFailure(pf);
            return;
        }

        VariJWTClaims variClaims = VariJWTClaims.parse(jwt);

        // set X-Vari-UserId header with vari_user_id claim
        Optional<Integer> userId = variClaims.getUserId();
        if (!userId.isPresent()) {
            PolicyFailure pf = getFailureFactory(context).createFailure(PolicyFailureType.Authentication,
                    MISSING_CLAIM, "Missing vari_user_id from token");
            pf.setResponseCode(HTTP_UNAUTHORIZED);
            chain.doFailure(pf);
            return;
        }
        userId.ifPresent(value -> request.getHeaders().put(VARI_USER_ID_HEADER, Integer.toString(value)));

        // set X-Vari-IDPUserId header with sub claim
        Optional<String> idpUserId = variClaims.getIdpUserId();
        if (!idpUserId.isPresent()) {
            PolicyFailure pf = getFailureFactory(context).createFailure(PolicyFailureType.Authentication,
                    MISSING_CLAIM, "Missing sub from token");
            pf.setResponseCode(HTTP_UNAUTHORIZED);
            chain.doFailure(pf);
            return;
        }
        idpUserId.ifPresent(value -> request.getHeaders().put(VARI_IDPUSER_ID_HEADER, value));

        // set X-Vari-Roles header with realm_access.roles claim
        if (variClaims.getRoles().isEmpty()) {
            PolicyFailure pf = getFailureFactory(context).createFailure(PolicyFailureType.Authentication,
                    MISSING_CLAIM, "Missing realm_access.roles from token");
            pf.setResponseCode(HTTP_UNAUTHORIZED);
            chain.doFailure(pf);
            return;
        }
        // FIXME? request.getHeaders().add(key, value) doesn't work as expected, the final request contains only one
        // header X-Vari-Roles and no multiple ones, so we'll pass only one X-Vari-Roles with the roles separated by
        // comma.
        String roles = String.join(",", variClaims.getRoles());
        request.getHeaders().put(VARI_ROLES_HEADER, roles);

        // set X-Vari-Organizations header with vari_organization_id claim
        if (variClaims.getOrganizations().isEmpty()) {
            PolicyFailure pf = getFailureFactory(context).createFailure(PolicyFailureType.Authentication,
                    MISSING_CLAIM, "Missing vari_organization_id from token");
            pf.setResponseCode(HTTP_UNAUTHORIZED);
            chain.doFailure(pf);
            return;
        }
        if (variClaims.getOrganizations().contains(0)) {
            request.getHeaders().put(VARI_ORGANIZATIONS_HEADER, "*");
        } else {
            // FIXME? request.getHeaders().add(key, value) doesn't work as expected, the final request contains only
            // one header X-Vari-Organization and no multiple ones, so we'll pass only one X-Vari-Role with the
            // organizations separated by comma.
            String organizations = variClaims.getOrganizations()
                    .stream().map(id -> Integer.toString(id)).collect(Collectors.joining(","));
            request.getHeaders().put(VARI_ORGANIZATIONS_HEADER, organizations);

            // if and org id is provided as parameter, check it against vari_organization_id
            if (request.getQueryParams().containsKey(ORG_QUERY_PARAM)) {
                List<String> orgs = request.getQueryParams().getAll(ORG_QUERY_PARAM);
                if (orgs.size() > 1) {
                    PolicyFailure pf = getFailureFactory(context).createFailure(PolicyFailureType.Other,
                            BAD_ORGANIZATION_PARAMETER, "At most one org query parameter can be used");
                    pf.setResponseCode(HTTP_BAD_REQUEST);
                    chain.doFailure(pf);
                    return;
                }
                try {
                    int orgId = Integer.parseInt(orgs.get(0));
                    if (!variClaims.getOrganizations().contains(orgId)) {
                        PolicyFailure pf = getFailureFactory(context).createFailure(PolicyFailureType.Authorization,
                                UNKNOWN_ORGANIZATION, "Unknown organization");
                        pf.setResponseCode(HTTP_UNAUTHORIZED);
                        chain.doFailure(pf);
                        return;
                    }
                } catch (NumberFormatException e) {
                    PolicyFailure pf = getFailureFactory(context).createFailure(PolicyFailureType.Other,
                            BAD_ORGANIZATION_PARAMETER, "Invalid org parameter value");
                    pf.setResponseCode(HTTP_BAD_REQUEST);
                    chain.doFailure(pf);
                    return;
                }
            }
        }

        // our services won't require this
        request.getHeaders().remove(AUTHORIZATION_HEADER);

        chain.doApply(request);
    }

    @Override
    public void apply(ApiResponse response, IPolicyContext context, Object config,
                      IPolicyChain<ApiResponse> chain) {
        chain.doApply(response);
    }

    private IPolicyFailureFactoryComponent getFailureFactory(IPolicyContext context) {
        return context.getComponent(IPolicyFailureFactoryComponent.class);
    }
}
