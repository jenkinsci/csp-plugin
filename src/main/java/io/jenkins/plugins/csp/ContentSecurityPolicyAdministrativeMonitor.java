package io.jenkins.plugins.csp;

import hudson.Extension;
import hudson.ExtensionList;
import hudson.model.AdministrativeMonitor;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import jenkins.model.Jenkins;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;

@Extension
@Restricted(NoExternalUse.class)
public class ContentSecurityPolicyAdministrativeMonitor extends AdministrativeMonitor {

    @Override
    public String getDisplayName() {
        return Messages.ContentSecurityPolicyAdministrativeMonitor_DisplayName();
    }

    @Override
    public boolean isActivated() {
        return isDisableReportOnly() || isEnableReportOnly();
    }

    public boolean isEnableReportOnly() {
        ContentSecurityPolicyConfiguration configuration =
                ExtensionList.lookupSingleton(ContentSecurityPolicyConfiguration.class);
        ContentSecurityPolicyManagementLink managementLink =
                ExtensionList.lookupSingleton(ContentSecurityPolicyManagementLink.class);
        return !configuration.isReportOnly() && !managementLink.getRecords().isEmpty();
    }

    public boolean isDisableReportOnly() {
        ContentSecurityPolicyConfiguration configuration =
                ExtensionList.lookupSingleton(ContentSecurityPolicyConfiguration.class);
        ContentSecurityPolicyManagementLink managementLink =
                ExtensionList.lookupSingleton(ContentSecurityPolicyManagementLink.class);
        return configuration.isReportOnly()
                && managementLink.getRecords().isEmpty()
                && Duration.between(managementLink.getStart(), Instant.now())
                                .compareTo(Duration.ofHours(ContentSecurityPolicyManagementLink.ROTATE_PERIOD_HOURS))
                        > 0;
    }

    @Override
    public boolean isSecurity() {
        return true;
    }

    @RequirePOST
    public HttpResponse doAct(@QueryParameter String dismiss) throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        if (dismiss != null) {
            disable(true);
        } else {
            ContentSecurityPolicyConfiguration configuration =
                    ExtensionList.lookupSingleton(ContentSecurityPolicyConfiguration.class);
            configuration.setReportOnly(!configuration.isReportOnly());
        }
        return HttpResponses.forwardToPreviousPage();
    }
}
