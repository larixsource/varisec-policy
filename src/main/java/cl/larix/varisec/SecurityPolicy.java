package cl.larix.varisec;

import io.apiman.common.logging.IApimanLogger;
import io.apiman.gateway.engine.beans.ApiRequest;
import io.apiman.gateway.engine.beans.ApiResponse;
import io.apiman.gateway.engine.beans.exceptions.ConfigurationParseException;
import io.apiman.gateway.engine.policy.IPolicy;
import io.apiman.gateway.engine.policy.IPolicyChain;
import io.apiman.gateway.engine.policy.IPolicyContext;

/**
 * Vari Security Policy.
 *
 * @author Jorge Riquelme jorge@larix.cl
 */
public class SecurityPolicy implements IPolicy {

    public SecurityPolicy() {
    }

    @Override
    public Object parseConfiguration(String jsonConfiguration) throws ConfigurationParseException {
        return null;
    }

    @Override
    public void apply(ApiRequest request, IPolicyContext context, Object config,
                      IPolicyChain<ApiRequest> chain) {
        IApimanLogger logger = context.getLogger(getClass());
        logger.info("Vari Security! Authorization is %s", request.getHeaders().get("Authorization"));
        chain.doApply(request);
    }

    @Override
    public void apply(ApiResponse response, IPolicyContext context, Object config,
                      IPolicyChain<ApiResponse> chain) {
        chain.doApply(response);
    }
}
