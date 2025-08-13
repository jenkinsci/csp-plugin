/*
 * The MIT License
 *
 * Copyright (c) 2024 CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package io.jenkins.plugins.csp;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.ExtensionList;
import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jenkins.model.Jenkins;
import jenkins.security.ResourceDomainConfiguration;
import jenkins.util.HttpServletFilter;
import org.apache.commons.lang3.StringUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.accmod.restrictions.suppressions.SuppressRestrictedWarnings;

/**
 * Inject the CSP header based on {@link ContentSecurityPolicyConfiguration} into Jenkins views.
 * The reporting URL is implemented by {@link ContentSecurityPolicyRootAction}.
 * At the {@link Filter} level, Stapler {@link Context} information is not available.
 * We later attempt to add Stapler {@link Context} information in {@link ContentSecurityPolicyDecorator}.
 */
@Extension
@Restricted(NoExternalUse.class)
public class ContentSecurityPolicyFilter implements HttpServletFilter {

    static String getConfiguredRules() {
        final String rule = ExtensionList.lookupSingleton(ContentSecurityPolicyConfiguration.class).getRule();
        if (rule == null) {
            return null;
        }
        return StringUtils.removeEnd(rule.trim(), ";");
    }

    static String getHeader() {
        final boolean reportOnly = ExtensionList.lookupSingleton(ContentSecurityPolicyConfiguration.class).isReportOnly();
        return reportOnly ? "Content-Security-Policy-Report-Only" : "Content-Security-Policy";
    }

    static String getValue(@NonNull String context) {
        final Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins != null) {
            final String rootUrl = jenkins.getRootUrl();
            if (rootUrl != null && jenkins.hasPermission(Jenkins.READ)) {
                return getConfiguredRules() + "; report-uri " + rootUrl + ContentSecurityPolicyRootAction.URL
                        + "/" + context;
            }
        }
        return getConfiguredRules();
    }

    @SuppressRestrictedWarnings({ResourceDomainConfiguration.class})
    @Override
    public boolean handle(HttpServletRequest req, HttpServletResponse rsp) {
        final String header = getHeader();
        if (rsp.getHeader(header) == null && !ResourceDomainConfiguration.isResourceRequest(req)) {
            /*
             * Set the header without Stapler context information at this low layer. We later attempt to add Stapler
             * context information in ContentSecurityPolicyDecorator.
             */
            String context = Context.encodeContext(
                    "",
                    Jenkins.getAuthentication2(),
                    StringUtils.removeStart(req.getRequestURI(), req.getContextPath()));
            rsp.setHeader(header, getValue(context));
        }
        return false;
    }
}
