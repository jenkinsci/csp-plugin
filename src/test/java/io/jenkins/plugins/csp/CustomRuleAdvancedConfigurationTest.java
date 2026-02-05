package io.jenkins.plugins.csp;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;

import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.misc.junit.jupiter.WithJenkinsConfiguredWithCode;
import java.lang.reflect.Field;
import java.util.Optional;
import jenkins.model.Jenkins;
import jenkins.security.csp.AdvancedConfiguration;
import jenkins.security.csp.Contributor;
import jenkins.security.csp.CspBuilder;
import jenkins.security.csp.CspHeader;
import jenkins.security.csp.CspHeaderDecider;
import jenkins.security.csp.Directive;
import jenkins.security.csp.impl.CspConfiguration;
import jenkins.security.csp.impl.DevelopmentHeaderDecider;
import org.htmlunit.WebResponse;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.For;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.TestExtension;
import org.jvnet.hudson.test.junit.jupiter.FlagExtension;

@For(CustomRuleAdvancedConfiguration.class)
@WithJenkinsConfiguredWithCode
class CustomRuleAdvancedConfigurationTest {

    @RegisterExtension
    @SuppressWarnings("unused")
    private final FlagExtension<Boolean> flagExtension = new FlagExtension<>(
            () -> {
                try {
                    Field field = DevelopmentHeaderDecider.class.getDeclaredField("DISABLED");
                    field.setAccessible(true);
                    return (Boolean) field.get(null);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            },
            (v) -> {
                try {
                    Field field = DevelopmentHeaderDecider.class.getDeclaredField("DISABLED");
                    field.setAccessible(true);
                    field.set(null, v);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            },
            true);

    @Test
    void testCoreDefaultRules(JenkinsConfiguredWithCodeRule j) {
        // These tests are sensitive to what the core default rules are, so assert these in isolation.
        final String rules = new CspBuilder().withDefaultContributions().build();
        assertThat(
                rules,
                equalTo(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline';"));
    }

    @Test
    @ConfiguredWithCode("Basics.yml")
    void testBasics(JenkinsConfiguredWithCodeRule j) throws Exception {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(j, CspHeader.ContentSecurityPolicy),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));

        // Ensure we have the correct decider in place for these tests
        final Optional<CspHeaderDecider> decider = CspHeaderDecider.getCurrentDecider();
        assertThat(decider.isPresent(), equalTo(true));
        assertThat(decider.get(), instanceOf(CspConfiguration.ConfigurationHeaderDecider.class));
    }

    @Test
    @ConfiguredWithCode("Readme.yml")
    void testReadme(JenkinsConfiguredWithCodeRule j) throws Exception {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(j, CspHeader.ContentSecurityPolicy),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' avatars.githubusercontent.com data:; object-src 'none'; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));

        final Optional<ReportingAdvancedConfiguration> reportingConfig =
                AdvancedConfiguration.getCurrent(ReportingAdvancedConfiguration.class);
        assertThat(reportingConfig.isPresent(), equalTo(true));
        assertThat(reportingConfig.get().isIgnoreAnonymousReports(), equalTo(true));
    }

    @Test
    @ConfiguredWithCode("UnsafeInline.yml")
    void testUnsafeInline(JenkinsConfiguredWithCodeRule j) throws Exception {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(j, CspHeader.ContentSecurityPolicy),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; script-src 'report-sample' 'self' 'unsafe-inline'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("UnsafeEval.yml")
    void testUnsafeEval(JenkinsConfiguredWithCodeRule j) throws Exception {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(j, CspHeader.ContentSecurityPolicy),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; script-src 'report-sample' 'self' 'unsafe-eval'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("DataScheme.yml")
    void testDataScheme(JenkinsConfiguredWithCodeRule j) throws Exception {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(j, CspHeader.ContentSecurityPolicy),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; script-src 'report-sample' 'self' data:; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("BlobScheme.yml")
    void testBlobScheme(JenkinsConfiguredWithCodeRule j) throws Exception {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(j, CspHeader.ContentSecurityPolicyReportOnly),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; script-src 'report-sample' 'self' blob:; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("SelfValue.yml")
    void testSelfValue(JenkinsConfiguredWithCodeRule j) throws Exception {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(j, CspHeader.ContentSecurityPolicyReportOnly),
                startsWith(
                        "base-uri 'none'; connect-src 'self'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("ResetInheriting.yml")
    void testResetInheriting(JenkinsConfiguredWithCodeRule j) throws Exception {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(j, CspHeader.ContentSecurityPolicy),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("MultipleRules.yml")
    void testMultipleRules(JenkinsConfiguredWithCodeRule j) throws Exception {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(j, CspHeader.ContentSecurityPolicy),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' blob: cdn.example.com data:; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("IterateOneDirective.yml")
    void testIterateOneDirective(JenkinsConfiguredWithCodeRule j) throws Exception {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(j, CspHeader.ContentSecurityPolicy),
                startsWith(
                        "base-uri 'none'; connect-src blob:; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("NavigationFormActionDomain.yml")
    void testNavigationFormActionDomain(JenkinsConfiguredWithCodeRule j) throws Exception {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(j, CspHeader.ContentSecurityPolicy),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self' external-form.example.com; frame-ancestors 'self'; img-src 'self' data:; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("NavigationFrameAncestorsDomain.yml")
    void testNavigationFrameAncestorsDomain(JenkinsConfiguredWithCodeRule j) throws Exception {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(j, CspHeader.ContentSecurityPolicy),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self' parent.example.com; img-src 'self' data:; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("NavigationSelfValueAfterReset.yml")
    void testNavigationSelfValueAfterReset(JenkinsConfiguredWithCodeRule j) throws Exception {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(j, CspHeader.ContentSecurityPolicyReportOnly),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("NavigationOtherValueAfterReset.yml")
    void testNavigationOtherValueAfterReset(JenkinsConfiguredWithCodeRule j) throws Exception {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(j, CspHeader.ContentSecurityPolicyReportOnly),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors trusted.example.com; img-src 'self' data:; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("NavigationMultipleRules.yml")
    void testNavigationMultipleRules(JenkinsConfiguredWithCodeRule j) throws Exception {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(j, CspHeader.ContentSecurityPolicy),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self' trusted1.example.com trusted2.example.com; img-src 'self' data:; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("NavigationBothDirectives.yml")
    void testNavigationBothDirectives(JenkinsConfiguredWithCodeRule j) throws Exception {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(j, CspHeader.ContentSecurityPolicy),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self' forms.example.com; frame-ancestors 'self' embed.example.com; img-src 'self' data:; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("InvalidDomain.yml")
    void testInvalidDomain(JenkinsConfiguredWithCodeRule j) throws Exception {
        final String cspPrefix =
                "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-";
        assertThat(getHeaderAndAssertTheOtherIsAbsent(j, CspHeader.ContentSecurityPolicy), startsWith(cspPrefix));

        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        j.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.ADMINISTER)
                .everywhere()
                .to("admin"));
        // This is an anonymous user:
        assertThat(getHeaderAndAssertTheOtherIsAbsent(j, CspHeader.ContentSecurityPolicy), startsWith(cspPrefix));
    }

    @Test
    @ConfiguredWithCode("ContributorsOrder.yml")
    void testContributorsOrder(JenkinsConfiguredWithCodeRule j) throws Exception {
        String cspPrefix =
                "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src cdn.example.com; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-";
        assertThat(getHeaderAndAssertTheOtherIsAbsent(j, CspHeader.ContentSecurityPolicy), startsWith(cspPrefix));
    }

    private static String getHeaderAndAssertTheOtherIsAbsent(JenkinsConfiguredWithCodeRule j, CspHeader header)
            throws Exception {
        try (JenkinsRule.WebClient wc = j.createWebClient().withThrowExceptionOnFailingStatusCode(false)) {
            final HtmlPage page = wc.goTo("");
            final WebResponse rsp = page.getWebResponse();
            final String cspHeader = rsp.getResponseHeaderValue(header.getHeaderName());
            assertThat(cspHeader, notNullValue());
            assertThat(
                    rsp.getResponseHeaderValue(
                            header == CspHeader.ContentSecurityPolicy
                                    ? CspHeader.ContentSecurityPolicyReportOnly.getHeaderName()
                                    : CspHeader.ContentSecurityPolicy.getHeaderName()),
                    nullValue());
            return cspHeader;
        }
    }

    @TestExtension({"testContributorsOrder"})
    public static class AAAAContributor implements Contributor {
        @Override
        public void apply(CspBuilder builder) {
            builder.add(Directive.IMG_SRC, "aaaa.example.com");
        }
    }

    @TestExtension({"testContributorsOrder"})
    public static class ZZZZContributor implements Contributor {
        @Override
        public void apply(CspBuilder builder) {
            builder.add(Directive.IMG_SRC, "zzzz.example.com");
        }
    }
}
