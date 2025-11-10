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
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.security.csp.AdvancedConfiguration;
import jenkins.security.csp.Contributor;
import jenkins.security.csp.CspBuilder;

@Extension
public class ContentSecurityPolicyContributor implements Contributor {

    private static final Logger LOGGER = Logger.getLogger(ContentSecurityPolicyContributor.class.getName());

    @Override
    public void apply(CspBuilder builder) {
        final Optional<CustomRuleAdvancedConfiguration> configuration =
                AdvancedConfiguration.getCurrent(CustomRuleAdvancedConfiguration.class);
        configuration.ifPresent(customRuleAdvancedConfiguration -> customRuleAdvancedConfiguration
                .getRules()
                .forEach(rule -> {
                    try {
                        rule.apply(builder);
                    } catch (RuntimeException e) {
                        LOGGER.log(Level.WARNING, "Exception trying to apply " + rule, e);
                    }
                }));
    }
}
