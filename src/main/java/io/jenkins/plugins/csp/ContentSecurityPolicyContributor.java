package io.jenkins.plugins.csp;

import hudson.Extension;
import hudson.ExtensionList;
import jenkins.security.csp.Contributor;
import jenkins.security.csp.CspBuilder;

@Extension
public class ContentSecurityPolicyContributor implements Contributor {
    @Override
    public void apply(CspBuilder builder) {
        ExtensionList.lookupSingleton(ContentSecurityPolicyConfiguration.class)
                .getRules()
                .forEach(rule -> rule.apply(builder));
    }
}
