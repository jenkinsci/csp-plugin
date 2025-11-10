/*
 * The MIT License
 *
 * Copyright (c) 2025 CloudBees, Inc.
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

import hudson.Extension;
import hudson.model.Saveable;
import hudson.util.DescribableList;
import java.io.IOException;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import jenkins.security.csp.AdvancedConfiguration;
import jenkins.security.csp.AdvancedConfigurationDescriptor;
import jenkins.security.csp.CspBuilder;
import jenkins.security.csp.Directive;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

public class CustomRuleAdvancedConfiguration extends AdvancedConfiguration {

    @DataBoundConstructor
    public CustomRuleAdvancedConfiguration() {}

    private DescribableList<CustomRule, CustomRuleDescriptor> rules = new DescribableList<>(Saveable.NOOP);

    public List<CustomRule> getRules() {
        return rules;
    }

    @DataBoundSetter
    public void setRules(List<CustomRule> rules) throws IOException {
        this.rules.replaceBy(rules);
    }

    // Jelly
    public static Map<String, String> getCurrentEffectiveRules() {
        return new CspBuilder().withDefaultContributions().buildDirectives();
    }

    public static List<Directive> getCurrentRules() {
        return new CspBuilder()
                .withDefaultContributions().getMergedDirectives().stream()
                        .sorted(Comparator.comparing(Directive::name))
                        .toList();
    }

    @Extension
    @Symbol("custom")
    public static class DescriptorImpl extends AdvancedConfigurationDescriptor {}
}
