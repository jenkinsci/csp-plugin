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
import hudson.ExtensionPoint;
import hudson.model.Describable;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import jenkins.security.csp.CspBuilder;
import jenkins.security.csp.Directive;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

public abstract class ValueSpecifier implements Describable<ValueSpecifier>, ExtensionPoint {

    protected abstract String getValue();

    /**
     * Applies this value specifier to the given directive, if applicable.
     * @param directive the directive to apply to
     * @param builder the CSP builder
     */
    public void apply(String directive, CspBuilder builder) {
        builder.add(directive, getValue());
    }

    public abstract static class ValueSpecifierDescriptor extends Descriptor<ValueSpecifier> {}

    public static class UnsafeInline extends ValueSpecifier {
        @DataBoundConstructor
        public UnsafeInline() {}

        @Override
        protected String getValue() {
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
        protected String getValue() {
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
        protected String getValue() {
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
        protected String getValue() {
            return Directive.SELF;
        }

        @Extension
        @Symbol("self")
        public static class DescriptorImpl extends ValueSpecifierDescriptor {}
    }

    public static class ByDomain extends ValueSpecifier {
        private static final Logger LOGGER = Logger.getLogger(ByDomain.class.getName());
        private final String domain;

        @DataBoundConstructor
        public ByDomain(String domain) {
            this.domain = domain;
        }

        public String getDomain() {
            return domain;
        }

        @Override
        protected String getValue() {
            return null; // unused
        }

        @Override
        public void apply(String directive, CspBuilder builder) {
            if (DescriptorImpl.checkDomainInternal(domain).kind == FormValidation.Kind.OK) {
                builder.add(directive, domain);
            } else {
                LOGGER.log(Level.FINE, "Not adding invalid domain to " + directive + ": " + domain);
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
                return checkDomainInternal(value);
            }

            private static FormValidation checkDomainInternal(String domain) {
                if (domain == null || domain.trim().isEmpty()) {
                    return FormValidation.error("Domain cannot be empty");
                }

                // Allow wildcards, domains with optional scheme and port
                if (domain.matches(
                        "^(https?://)?([*]\\.|[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\\.)*[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(:[0-9]{1,5})?$")) {
                    return FormValidation.ok();
                }

                return FormValidation.error("Invalid domain format");
            }
        }
    }
}
