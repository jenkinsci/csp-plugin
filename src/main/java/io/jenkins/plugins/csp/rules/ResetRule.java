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
import io.jenkins.plugins.csp.CustomRuleDescriptor;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import jenkins.model.Jenkins;
import jenkins.security.csp.CspBuilder;
import jenkins.security.csp.CspHeader;
import jenkins.security.csp.Directive;
import jenkins.security.csp.FetchDirective;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

public class ResetRule extends CustomRule {

    private final String directive;
    private final boolean disableInheritance;

    @DataBoundConstructor
    public ResetRule(String directive, boolean disableInheritance) {
        this.directive = directive;
        this.disableInheritance = disableInheritance;
    }

    public String getDirective() {
        return directive;
    }

    @Override
    public void apply(CspBuilder builder) {
        builder.remove(directive);
        FetchDirective.toFetchDirective(directive).ifPresent(fd -> {
            if (isDisableInheritance()) {
                builder.initialize(fd);
            }
        });
    }

    public boolean isDisableInheritance() {
        return disableInheritance;
    }

    @Symbol("reset")
    @Extension
    public static class DescriptorImpl extends CustomRuleDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return "Reset directive";
        }

        @POST
        public ListBoxModel doFillDirectiveItems() {
            ListBoxModel model = new ListBoxModel();
            if (Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                Arrays.stream(FetchDirective.values())
                        .map(FetchDirective::toKey)
                        .forEach(model::add);
            }
            // Core sets these to 'self' by default, so we include them here to allow opening them up.
            List.of(Directive.FORM_ACTION, Directive.FRAME_ANCESTORS).forEach(model::add);
            return model;
        }

        @POST
        public FormValidation doCheckDirective(
                @QueryParameter String value, @QueryParameter boolean disableInheritance) {
            if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                return FormValidation.ok();
            }
            return FetchDirective.toFetchDirective(value)
                    .map(fd -> {
                        /*
                         * This list is based on knowledge of BaseContributor implementation details. Technically,
                         * we can probably exclude img-src from this list, but the UI will still look pretty broken.
                         */
                        if (List.of(
                                        FetchDirective.DEFAULT_SRC,
                                        FetchDirective.IMG_SRC,
                                        FetchDirective.SCRIPT_SRC,
                                        FetchDirective.STYLE_SRC)
                                .contains(fd)) {
                            return FormValidation.warningWithMarkup(
                                    "Resetting " + fd.toKey()
                                            + " to 'none' is discouraged. The Jenkins UI may break unless you're careful. If this happens, you can restart Jenkins with the Java system property '<code>"
                                            + CspHeader.class.getName()
                                            + ".selectedHeaderName</code>' set to '<code>Content-Security-Policy-Report-Only</code>' to recover.");
                        }
                        if (disableInheritance && fd.getFallback() != null) {
                            /* We need to check connect-src here, because it's required for AJAX behavior, but is undefined by default */
                            if (List.of(FetchDirective.STYLE_SRC, FetchDirective.SCRIPT_SRC)
                                            .contains(fd.getFallback())
                                    || Objects.equals(FetchDirective.CONNECT_SRC, fd)) {
                                return FormValidation.warningWithMarkup(
                                        "Resetting " + fd.toKey()
                                                + " to 'none' with disabled inheritance is discouraged. The Jenkins UI may break unless you're careful. If this happens, you can restart Jenkins with the Java system property '<code>"
                                                + CspHeader.class.getName()
                                                + ".selectedHeaderName</code>' set to '<code>Content-Security-Policy-Report-Only</code>' to recover.");
                            }
                        }
                        return FormValidation.ok();
                    })
                    .orElse(FormValidation.ok());
        }

        @POST
        public FormValidation doCheckDisableInheritance(
                @QueryParameter boolean value, @QueryParameter String directive) {
            if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                return FormValidation.ok();
            }
            if (value && !FetchDirective.isFetchDirective(directive)) {
                return FormValidation.warningWithMarkup(
                        "The directive '<code>" + Util.xmlEscape(directive)
                                + "</code>' is not a fetch directive with inheritance, so the inheritance option has no effect.");
            }
            return FormValidation.ok();
        }
    }
}
