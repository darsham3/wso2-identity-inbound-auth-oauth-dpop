package org.wso2.carbon.identity.oauth.dpop.listener;

import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;

public class DPoPServiceComponent {
    protected void activate(ComponentContext context){
        BundleContext bundleContext = context.getBundleContext();
        bundleContext.registerService(OAuthEventInterceptor.class, new OAuthDPoPTokenEventHandler(),null);
    }
}
