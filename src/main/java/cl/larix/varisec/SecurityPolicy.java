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

import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Vari Security Policy.
 *
 * @author Jorge Riquelme (jorge@larix.cl)
 */
public class SecurityPolicy implements IPolicy {

    private static final String AUTHORIZATION_KEY = "Authorization";
    private static final String ACCESS_TOKEN_QUERY_KEY = "access_token";
    private static final String BEARER = "bearer ";
    private static final int HTTP_UNAUTHORIZED = 401;
    private static final int AUTH_NOT_PROVIDED = 12005;
    private static final int MISSING_CLAIM = 12009;

    public SecurityPolicy() {
    }

    @Override
    public Object parseConfiguration(String jsonConfiguration) throws ConfigurationParseException {
        return null;
    }

    @Override
    public void apply(ApiRequest request, IPolicyContext context, Object config,
                      IPolicyChain<ApiRequest> chain) {
        String jwt = Optional.ofNullable(request.getHeaders().get(AUTHORIZATION_KEY))
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

        VariJWTClaims variClaims = VariJWTUtil.parse(jwt);

        Optional<Integer> userId = variClaims.getUserId();
        if (userId.isPresent()) {
            userId.ifPresent(value -> request.getHeaders().put("X-Vari-UserId", Integer.toString(value)));
        } else {
            PolicyFailure pf = getFailureFactory(context).createFailure(PolicyFailureType.Authentication,
                    MISSING_CLAIM, "Missing vari_user_id from token");
            pf.setResponseCode(HTTP_UNAUTHORIZED);
            chain.doFailure(pf);
            return;
        }

        Optional<String> idpUserId = variClaims.getIdpUserId();
        if (idpUserId.isPresent()) {
            idpUserId.ifPresent(value -> request.getHeaders().put("X-Vari-IDPUserId", value));
        } else {
            PolicyFailure pf = getFailureFactory(context).createFailure(PolicyFailureType.Authentication,
                    MISSING_CLAIM, "Missing sub from token");
            pf.setResponseCode(HTTP_UNAUTHORIZED);
            chain.doFailure(pf);
            return;
        }

        if (!variClaims.getRoles().isEmpty()) {
            // FIXME? request.getHeaders().add(key, value) doesn't work as expected, the final request contains only one
            // header X-Vari-Role and no multiple ones, so we'll pass only one X-Vari-Role with the roles separated by comma.
            String roles = String.join(",", variClaims.getRoles());
            request.getHeaders().put("X-Vari-Role", roles);
        } else {
            PolicyFailure pf = getFailureFactory(context).createFailure(PolicyFailureType.Authentication,
                    MISSING_CLAIM, "Missing realm_access.roles from token");
            pf.setResponseCode(HTTP_UNAUTHORIZED);
            chain.doFailure(pf);
            return;
        }

        if (!variClaims.getOrganizations().isEmpty()) {
            if (variClaims.getOrganizations().contains(0)) {
                request.getHeaders().put("X-Vari-Organization", "*");
            } else {
                // FIXME? request.getHeaders().add(key, value) doesn't work as expected, the final request contains only
                // one header X-Vari-Organization and no multiple ones, so we'll pass only one X-Vari-Role with the
                // organizations separated by comma.
                String organizations = variClaims.getOrganizations()
                        .stream().map(id -> Integer.toString(id)).collect(Collectors.joining(","));
                request.getHeaders().put("X-Vari-Organization", organizations);
            }
        } else {
            PolicyFailure pf = getFailureFactory(context).createFailure(PolicyFailureType.Authentication,
                    MISSING_CLAIM, "Missing vari_organization_id from token");
            pf.setResponseCode(HTTP_UNAUTHORIZED);
            chain.doFailure(pf);
            return;
        }

        // our services won't require this
        request.getHeaders().remove("Authorization");

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
