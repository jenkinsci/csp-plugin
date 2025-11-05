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
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import hudson.model.PersistentDescriptor;
import hudson.util.DescribableList;
import java.io.IOException;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import jenkins.model.GlobalConfiguration;
import jenkins.model.GlobalConfigurationCategory;
import jenkins.security.csp.CspBuilder;
import jenkins.security.csp.Directive;
import org.jenkinsci.Symbol;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundSetter;

/**
 * Customize the Content Security Policy rules.
 */
@Extension
@Restricted(NoExternalUse.class)
@Symbol("contentSecurityPolicyConfiguration")
public class ContentSecurityPolicyConfiguration extends GlobalConfiguration implements PersistentDescriptor {

    public static final String DEFAULT_RULE =
            "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: ; script-src 'self' 'report-sample' usage.jenkins.io;";

    /**
     * @deprecated v1 configuration.
     */
    // TODO How to keep?
    @Deprecated
    @SuppressFBWarnings("URF_UNREAD_FIELD")
    private transient boolean reportOnly = true;

    private DescribableList<CustomRule, CustomRuleDescriptor> rules = new DescribableList<>(this);

    /**
     * @deprecated v1 configuration. Has no effect any longer.
     */
    @Deprecated
    private transient String rule;

    @NonNull
    @Override
    public GlobalConfigurationCategory getCategory() {
        return GlobalConfigurationCategory.get(GlobalConfigurationCategory.Security.class);
    }

    public List<CustomRule> getRules() {
        return rules;
    }

    @DataBoundSetter
    public void setRules(List<CustomRule> rules) throws IOException {
        this.rules.replaceBy(rules);
        this.save();
    }

    // Jelly
    public static Map<String, String> getCurrentEffectiveRules() {
        return new CspBuilder().withDefaultContributions().buildDirectives();
    }

    public static List<Directive> getCurrentRules() {
        return new CspBuilder().withDefaultContributions().getMergedDirectives().stream().sorted(Comparator.comparing(Directive::name)).toList();
    }
}
