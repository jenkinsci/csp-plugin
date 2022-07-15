/*
 * The MIT License
 *
 * Copyright (c) 2021 Daniel Beck
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
import jenkins.model.GlobalConfiguration;
import jenkins.model.GlobalConfigurationCategory;
import org.jenkinsci.Symbol;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundSetter;

/**
 * Customize the Content-Security-Policy rules.
 */
@Extension
@Restricted(NoExternalUse.class)
@Symbol("contentSecurityPolicyConfiguration")
public class ContentSecurityPolicyConfiguration extends GlobalConfiguration {

    public static final String DEFAULT_RULE = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: ; script-src 'self' 'report-sample' usage.jenkins.io;";
            // Hashes for known static core scripts could be added to limit spam:
            // 'sha256-z4DDyDYJv6wQlqKsZeAc/6+Aanuong2YoqhblTEpsME=' screenResolution
            // 'sha256-z/buOmKIvbplzl42NzWxG3io200i1Ln7VCsKlSDq2qs=' var amContainer

    private boolean reportOnly = true;

    private String rule = DEFAULT_RULE;

    @NonNull
    @Override
    public GlobalConfigurationCategory getCategory() {
        return GlobalConfigurationCategory.get(GlobalConfigurationCategory.Security.class);
    }

    public String getRule() {
        return rule;
    }

    @DataBoundSetter
    public void setRule(String rule) {
        this.rule = rule;
        save();
    }

    public boolean isReportOnly() {
        return reportOnly;
    }

    @DataBoundSetter
    public void setReportOnly(boolean reportOnly) {
        this.reportOnly = reportOnly;
        save();
    }
}
