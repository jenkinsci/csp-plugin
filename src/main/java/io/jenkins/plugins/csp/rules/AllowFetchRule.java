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
package io.jenkins.plugins.csp.rules;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.Util;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import io.jenkins.plugins.csp.CustomRule;
import io.jenkins.plugins.csp.CustomRuleAdvancedConfiguration;
import io.jenkins.plugins.csp.CustomRuleDescriptor;
import java.util.Arrays;
import java.util.Optional;
import jenkins.model.Jenkins;
import jenkins.security.csp.CspBuilder;
import jenkins.security.csp.Directive;
import jenkins.security.csp.FetchDirective;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

public class AllowFetchRule extends CustomRule {
    private final String directive;
    private final ValueSpecifier allow;

    @DataBoundConstructor
    public AllowFetchRule(String directive, ValueSpecifier allow) {
        this.directive = directive;
        this.allow = allow;
    }

    public String getDirective() {
        return directive;
    }

    public ValueSpecifier getAllow() {
        return allow;
    }

    @Override
    public void apply(CspBuilder builder) {
        allow.apply(directive, builder);
    }

    @Symbol("allowFetch")
    @Extension
    public static class DescriptorImpl extends CustomRuleDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return "Allow additional fetch source";
        }

        @POST
        public FormValidation doCheckDirective(@QueryParameter String value) {
            if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                return FormValidation.ok();
            }
            if (value == null || value.isEmpty()) {
                return FormValidation.ok();
            }
            if (FetchDirective.isFetchDirective(value)) {
                FetchDirective fetchDirective = FetchDirective.fromKey(value);
                final Optional<Directive> directive = CustomRuleAdvancedConfiguration.getCurrentRules().stream()
                        .filter(it -> it.name().equals(value))
                        .findFirst();
                if (directive.isEmpty()) {
                    return FormValidation.okWithMarkup(
                            "This directive is currently undefined and would fall back to <code>"
                                    + Util.xmlEscape(
                                            fetchDirective.getFallback().toKey()) + "</code>.");
                }
                final Directive effectiveDirective = directive.get();
                if (effectiveDirective.inheriting()) {
                    return FormValidation.okWithMarkup("This directive inherits from '<code>"
                            + fetchDirective.getFallback().toKey() + "</code>'. Its current effective value is <code>"
                            + Util.xmlEscape(String.join(" ", effectiveDirective.values())) + "</code>");
                } else {
                    return FormValidation.okWithMarkup(
                            "This directive is non-inheriting. Its current effective value is <code>"
                                    + Util.xmlEscape(String.join(" ", effectiveDirective.values())) + "</code>");
                }
            }
            return FormValidation.error("Not a known fetch directive: " + value);
        }

        @POST
        public ListBoxModel doFillDirectiveItems() {
            ListBoxModel model = new ListBoxModel();
            if (Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                Arrays.stream(FetchDirective.values())
                        .map(FetchDirective::toKey)
                        .forEach(model::add);
            }
            return model;
        }
    }
}
