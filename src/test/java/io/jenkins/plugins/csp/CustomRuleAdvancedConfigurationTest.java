package io.jenkins.plugins.csp;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;

import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import java.io.IOException;
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
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.FlagRule;
import org.jvnet.hudson.test.For;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.TestExtension;
import org.xml.sax.SAXException;

@For(CustomRuleAdvancedConfiguration.class)
public class CustomRuleAdvancedConfigurationTest {

    static Field developmentHeaderDeciderDisabledField;

    static {
        try {
            developmentHeaderDeciderDisabledField = DevelopmentHeaderDecider.class.getDeclaredField("DISABLED");
            developmentHeaderDeciderDisabledField.setAccessible(true);
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        }
    }

    @Rule
    public JenkinsConfiguredWithCodeRule j = new JenkinsConfiguredWithCodeRule();

    @Rule
    public FlagRule<Boolean> flagRule = new FlagRule<>(
            () -> {
                try {
                    return (Boolean) developmentHeaderDeciderDisabledField.get(null);
                } catch (IllegalAccessException e) {
                    throw new RuntimeException(e);
                }
            },
            (v) -> {
                try {
                    developmentHeaderDeciderDisabledField.set(null, v);
                } catch (IllegalAccessException e) {
                    throw new RuntimeException(e);
                }
            },
            true);

    @Test
    public void testCoreDefaultRules() {
        // These tests are sensitive to what the core default rules are, so assert these in isolation.
        final String rules = new CspBuilder().withDefaultContributions().build();
        assertThat(
                rules,
                equalTo(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline';"));
    }

    @Test
    @ConfiguredWithCode("Basics.yml")
    public void testBasics() throws IOException, SAXException {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(CspHeader.ContentSecurityPolicy),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));

        // Ensure we have the correct decider in place for these tests
        final Optional<CspHeaderDecider> decider = CspHeaderDecider.getCurrentDecider();
        assertThat(decider.isPresent(), equalTo(true));
        assertThat(decider.get(), instanceOf(CspConfiguration.ConfigurationHeaderDecider.class));
    }

    @Test
    @ConfiguredWithCode("Readme.yml")
    public void testReadme() throws IOException, SAXException {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(CspHeader.ContentSecurityPolicy),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' avatars.githubusercontent.com data:; object-src 'none'; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));

        final Optional<ReportingAdvancedConfiguration> reportingConfig =
                AdvancedConfiguration.getCurrent(ReportingAdvancedConfiguration.class);
        assertThat(reportingConfig.isPresent(), equalTo(true));
        assertThat(reportingConfig.get().isIgnoreAnonymousReports(), equalTo(true));
    }

    @Test
    @ConfiguredWithCode("UnsafeInline.yml")
    public void testUnsafeInline() throws IOException, SAXException {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(CspHeader.ContentSecurityPolicy),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; script-src 'report-sample' 'self' 'unsafe-inline'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("UnsafeEval.yml")
    public void testUnsafeEval() throws IOException, SAXException {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(CspHeader.ContentSecurityPolicy),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; script-src 'report-sample' 'self' 'unsafe-eval'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("DataScheme.yml")
    public void testDataScheme() throws IOException, SAXException {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(CspHeader.ContentSecurityPolicy),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; script-src 'report-sample' 'self' data:; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("BlobScheme.yml")
    public void testBlobScheme() throws IOException, SAXException {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(CspHeader.ContentSecurityPolicyReportOnly),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; script-src 'report-sample' 'self' blob:; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("SelfValue.yml")
    public void testSelfValue() throws IOException, SAXException {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(CspHeader.ContentSecurityPolicyReportOnly),
                startsWith(
                        "base-uri 'none'; connect-src 'self'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("ResetInheriting.yml")
    public void testResetInheriting() throws IOException, SAXException {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(CspHeader.ContentSecurityPolicy),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("MultipleRules.yml")
    public void testMultipleRules() throws IOException, SAXException {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(CspHeader.ContentSecurityPolicy),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' blob: cdn.example.com data:; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("IterateOneDirective.yml")
    public void testIterateOneDirective() throws IOException, SAXException {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(CspHeader.ContentSecurityPolicy),
                startsWith(
                        "base-uri 'none'; connect-src blob:; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("NavigationFormActionDomain.yml")
    public void testNavigationFormActionDomain() throws IOException, SAXException {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(CspHeader.ContentSecurityPolicy),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self' external-form.example.com; frame-ancestors 'self'; img-src 'self' data:; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("NavigationFrameAncestorsDomain.yml")
    public void testNavigationFrameAncestorsDomain() throws IOException, SAXException {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(CspHeader.ContentSecurityPolicy),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self' parent.example.com; img-src 'self' data:; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("NavigationSelfValueAfterReset.yml")
    public void testNavigationSelfValueAfterReset() throws IOException, SAXException {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(CspHeader.ContentSecurityPolicyReportOnly),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("NavigationOtherValueAfterReset.yml")
    public void testNavigationOtherValueAfterReset() throws IOException, SAXException {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(CspHeader.ContentSecurityPolicyReportOnly),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors trusted.example.com; img-src 'self' data:; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("NavigationMultipleRules.yml")
    public void testNavigationMultipleRules() throws IOException, SAXException {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(CspHeader.ContentSecurityPolicy),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self' trusted1.example.com trusted2.example.com; img-src 'self' data:; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("NavigationBothDirectives.yml")
    public void testNavigationBothDirectives() throws IOException, SAXException {
        assertThat(
                getHeaderAndAssertTheOtherIsAbsent(CspHeader.ContentSecurityPolicy),
                startsWith(
                        "base-uri 'none'; default-src 'self'; form-action 'self' forms.example.com; frame-ancestors 'self' embed.example.com; img-src 'self' data:; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-"));
    }

    @Test
    @ConfiguredWithCode("InvalidDomain.yml")
    public void testInvalidDomain() throws IOException, SAXException {
        final String cspPrefix =
                "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-";
        assertThat(getHeaderAndAssertTheOtherIsAbsent(CspHeader.ContentSecurityPolicy), startsWith(cspPrefix));

        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        j.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.ADMINISTER)
                .everywhere()
                .to("admin"));
        // This is an anonymous user:
        assertThat(getHeaderAndAssertTheOtherIsAbsent(CspHeader.ContentSecurityPolicy), startsWith(cspPrefix));
    }

    @Test
    @ConfiguredWithCode("ContributorsOrder.yml")
    public void testContributorsOrder() throws IOException, SAXException {
        String cspPrefix =
                "base-uri 'none'; default-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src cdn.example.com; script-src 'report-sample' 'self'; style-src 'report-sample' 'self' 'unsafe-inline'; report-";
        ;
        assertThat(getHeaderAndAssertTheOtherIsAbsent(CspHeader.ContentSecurityPolicy), startsWith(cspPrefix));
    }

    private String getHeaderAndAssertTheOtherIsAbsent(CspHeader header) throws IOException, SAXException {
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
