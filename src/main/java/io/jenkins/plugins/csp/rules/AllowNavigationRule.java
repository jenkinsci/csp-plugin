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
import hudson.model.Descriptor;
import hudson.util.ListBoxModel;
import io.jenkins.plugins.csp.CustomRule;
import io.jenkins.plugins.csp.CustomRuleDescriptor;
import java.util.List;
import jenkins.model.Jenkins;
import jenkins.security.csp.CspBuilder;
import jenkins.security.csp.Directive;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.verb.POST;

/**
 * Allow additional sources for navigation directives (frame-ancestors, form-action).
 * These only support 'self' ({@link io.jenkins.plugins.csp.rules.ValueSpecifier.Self}),
 * host sources ({@link io.jenkins.plugins.csp.rules.ValueSpecifier.ByDomain}), and scheme sources.
 * There are no useful scheme sources for these directives, so we do not support those.
 * @see io.jenkins.plugins.csp.rules.AllowNavigationRule.DescriptorImpl#getAllowDescriptors()
 * @see <a href="https://www.w3.org/TR/CSP3/#directive-frame-ancestors">CSP3: frame-ancestors</a>
 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/form-action">MDN: form-action</a>
 */
// frame-ancestors has: `ancestor-source      = scheme-source / host-source / "'self'"`
// form-action: "For this directive, the following source expression values are applicable: <host-source>
// <scheme-source> 'self'"
public class AllowNavigationRule extends CustomRule {
    private final String directive;
    private final ValueSpecifier allow;

    @DataBoundConstructor
    public AllowNavigationRule(String directive, ValueSpecifier allow) {
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

    @Symbol("allowNavigation")
    @Extension
    public static class DescriptorImpl extends CustomRuleDescriptor {

        @NonNull
        @Override
        public String getDisplayName() {
            return "Allow additional navigation source";
        }

        /**
         * Limit which descriptors are available for selection.
         * @return the allowed {@link io.jenkins.plugins.csp.rules.ValueSpecifier.ValueSpecifierDescriptor}s:
         * {@link io.jenkins.plugins.csp.rules.ValueSpecifier.Self} and
         * {@link io.jenkins.plugins.csp.rules.ValueSpecifier.ByDomain}.
         */
        public List<Descriptor<ValueSpecifier>> getAllowDescriptors() {
            return Jenkins.get().getDescriptorList(ValueSpecifier.class).stream()
                    .filter(d -> d instanceof ValueSpecifier.ByDomain.DescriptorImpl
                            || d instanceof ValueSpecifier.Self.DescriptorImpl)
                    .toList();
        }

        @POST
        public ListBoxModel doFillDirectiveItems() {
            ListBoxModel model = new ListBoxModel();
            if (Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                List.of(Directive.FORM_ACTION, Directive.FRAME_ANCESTORS).forEach(model::add);
            }
            return model;
        }
    }
}
