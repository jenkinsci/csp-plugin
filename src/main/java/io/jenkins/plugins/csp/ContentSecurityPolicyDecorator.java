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

import hudson.Extension;
import hudson.model.PageDecorator;
import jenkins.model.Jenkins;
import org.jenkinsci.Symbol;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.Ancestor;
import org.kohsuke.stapler.Stapler;

import java.util.List;

/**
 * Inject the CSP header based on {@link ContentSecurityPolicyConfiguration} into Jenkins views.
 * The reporting URL is implemented by {@link ContentSecurityPolicyRootAction}.
 */
@Extension
@Restricted(NoExternalUse.class)
@Symbol("contentSecurityPolicyDecorator")
public class ContentSecurityPolicyDecorator extends PageDecorator {

    private static String getContext() {

        final List<Ancestor> ancestors = Stapler.getCurrentRequest2().getAncestors();
        if (ancestors.isEmpty()) {
            // probably doesn't happen?
            return "";
        }
        Ancestor nearest = ancestors.get(ancestors.size() - 1);
        Object nearestObjectName = nearest.getObject().getClass().getName();
        String restOfUrl = nearest.getRestOfUrl();

        return Context.encodeContext(nearestObjectName, Jenkins.getAuthentication2(), restOfUrl);
    }

    public static void setHeader() {
        // Avoiding <st:header> because that adds an additional header rather than replacing the existing one.
        String context = getContext();
        Stapler.getCurrentResponse2()
                .setHeader(ContentSecurityPolicyFilter.getHeader(), ContentSecurityPolicyFilter.getValue(context));
    }
}
