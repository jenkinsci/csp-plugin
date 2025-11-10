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
import hudson.ExtensionList;
import hudson.ExtensionPoint;
import hudson.Util;
import hudson.model.Describable;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import io.jenkins.plugins.csp.CustomRule;
import io.jenkins.plugins.csp.CustomRuleAdvancedConfiguration;
import io.jenkins.plugins.csp.CustomRuleDescriptor;
import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
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
                    return FormValidation.okWithMarkup("This directive inherits from from '<code>"
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

    public abstract static class ValueSpecifier implements Describable<ValueSpecifier>, ExtensionPoint {
        abstract String getValue();

        public void apply(String directive, CspBuilder builder) {
            builder.add(directive, getValue());
        }
    }

    public abstract static class ValueSpecifierDescriptor extends Descriptor<ValueSpecifier> {}

    public static class UnsafeInline extends ValueSpecifier {
        @DataBoundConstructor
        public UnsafeInline() {}

        @Override
        String getValue() {
            return Directive.UNSAFE_INLINE;
        }

        @Extension
        public static class DescriptorImpl extends ValueSpecifierDescriptor {
            @NonNull
            @Override
            public String getDisplayName() {
                return "unsafe-inline";
            }
        }
    }

    public static class UnsafeEval extends ValueSpecifier {
        @DataBoundConstructor
        public UnsafeEval() {}

        @Override
        String getValue() {
            return Directive.UNSAFE_EVAL;
        }

        @Extension
        public static class DescriptorImpl extends ValueSpecifierDescriptor {
            @NonNull
            @Override
            public String getDisplayName() {
                return "unsafe-eval";
            }
        }
    }

    private abstract static class Scheme extends ValueSpecifier {
        @Override
        String getValue() {
            return getClass().getSimpleName().toLowerCase(Locale.ROOT) + ":";
        }
    }

    private abstract static class SchemeDescriptor extends ValueSpecifierDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return "Scheme " + getClass().getEnclosingClass().getSimpleName().toLowerCase(Locale.ROOT) + ":";
        }
    }

    public static class Data extends Scheme {
        @DataBoundConstructor
        public Data() {}

        @Extension
        @Symbol("dataScheme")
        public static class DescriptorImpl extends SchemeDescriptor {}
    }

    public static class Blob extends Scheme {
        @DataBoundConstructor
        public Blob() {}

        @Extension
        @Symbol("blobScheme")
        public static class DescriptorImpl extends SchemeDescriptor {}
    }

    public static class Self extends ValueSpecifier {
        @DataBoundConstructor
        public Self() {}

        @Override
        String getValue() {
            return Directive.SELF;
        }

        @Extension
        @Symbol("self")
        public static class DescriptorImpl extends ValueSpecifierDescriptor {}
    }

    public static class ByDomain extends ValueSpecifier {
        private final String domain;

        @DataBoundConstructor
        public ByDomain(String domain) {
            this.domain = domain;
        }

        public String getDomain() {
            return domain;
        }

        @Override
        String getValue() {
            return "'" + domain + "'";
        }

        @Override
        public void apply(String directive, CspBuilder builder) {
            if (ExtensionList.lookupSingleton(DescriptorImpl.class).doCheckDomain(domain).kind
                    == FormValidation.Kind.OK) {
                builder.add(directive, domain);
            } else {
                Logger.getLogger(ByDomain.class.getName())
                        .log(Level.FINE, "Not adding invalid domain to " + directive + ": " + domain);
            }
        }

        @Extension
        public static class DescriptorImpl extends ValueSpecifierDescriptor {
            @NonNull
            @Override
            public String getDisplayName() {
                return "Domain specification";
            }

            @POST
            public FormValidation doCheckDomain(@QueryParameter String value) {
                if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                    return FormValidation.ok();
                }
                if (value == null || value.trim().isEmpty()) {
                    return FormValidation.error("Domain cannot be empty");
                }

                // Allow wildcards, domains with optional scheme and port
                if (value.matches(
                        "^(https?://)?([*]\\.|[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\\.)*[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(:[0-9]{1,5})?$")) {
                    return FormValidation.ok();
                }

                return FormValidation.error("Invalid domain format");
            }
        }
    }
}
