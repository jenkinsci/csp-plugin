package io.jenkins.plugins.csp;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;

import hudson.ExtensionList;
import hudson.model.DirectoryBrowserSupport;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import jenkins.security.ResourceDomainConfiguration;
import org.htmlunit.Page;
import org.htmlunit.WebResponse;
import org.htmlunit.html.HtmlPage;
import org.htmlunit.util.NameValuePair;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.FlagRule;
import org.jvnet.hudson.test.JenkinsRule;
import org.kohsuke.accmod.restrictions.suppressions.SuppressRestrictedWarnings;
import org.xml.sax.SAXException;

public class ContentSecurityPolicyFilterTest {
    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Rule
    public FlagRule dbsCsp = FlagRule.systemProperty(DBS_CSP_SYSTEM_PROPERTY);

    @Test
    public void testRegularPageHeaders() throws IOException, SAXException {
        try (JenkinsRule.WebClient wc = j.createWebClient()) {
            final HtmlPage htmlPage = wc.goTo("userContent/");
            assertThat(htmlPage.getWebResponse().getStatusCode(), is(200));
            final List<NameValuePair> cspHeaders = htmlPage.getWebResponse().getResponseHeaders().stream()
                    .filter(p -> p.getName().startsWith(CONTENT_SECURITY_POLICY_HEADER))
                    .collect(Collectors.toList());
            assertThat(cspHeaders.size(), is(1));
            assertThat(cspHeaders.get(0).getValue(), startsWith(ContentSecurityPolicyConfiguration.DEFAULT_RULE));
        }
    }

    @Test
    public void testBundledResource() throws IOException, SAXException {
        try (JenkinsRule.WebClient wc = j.createWebClient().withThrowExceptionOnFailingStatusCode(false)) {
            final Page page = wc.goTo("apple-touch-icon.png", "image/png");
            assertThat(page.getWebResponse().getStatusCode(), is(200));
            final List<NameValuePair> cspHeaders = page.getWebResponse().getResponseHeaders().stream()
                    .filter(p -> p.getName().startsWith(CONTENT_SECURITY_POLICY_HEADER))
                    .collect(Collectors.toList());
            assertThat(cspHeaders.size(), is(1));
            assertThat(cspHeaders.get(0).getValue(), startsWith(ContentSecurityPolicyConfiguration.DEFAULT_RULE));
        }
    }

    @Test
    public void test404ErrorHeaders() throws IOException, SAXException {
        try (JenkinsRule.WebClient wc = j.createWebClient().withThrowExceptionOnFailingStatusCode(false)) {
            final HtmlPage htmlPage = wc.goTo("thisUrlDoesNotExist");
            assertThat(htmlPage.getWebResponse().getStatusCode(), is(404));
            final List<NameValuePair> cspHeaders = htmlPage.getWebResponse().getResponseHeaders().stream()
                    .filter(p -> p.getName().startsWith(CONTENT_SECURITY_POLICY_HEADER))
                    .collect(Collectors.toList());
            assertThat(cspHeaders.size(), is(1));
            assertThat(cspHeaders.get(0).getValue(), startsWith(ContentSecurityPolicyConfiguration.DEFAULT_RULE));
        }
    }

    @SuppressRestrictedWarnings({DirectoryBrowserSupport.class})
    @Test
    public void directoryBrowserSupportContradictsCspPluginWithReporting() throws IOException, SAXException {
        try (JenkinsRule.WebClient wc = j.createWebClient()) {
            final Page page = wc.goTo("userContent/readme.txt", "text/plain");
            assertThat(page.getWebResponse().getStatusCode(), is(200));
            final Map<String, String> cspHeaders = getCspResponseHeadersMap(page.getWebResponse());
            assertThat(cspHeaders.size(), is(CSP_HEADERS.size()));
            assertThat(
                    cspHeaders.get(CONTENT_SECURITY_POLICY_REPORT_ONLY_HEADER),
                    startsWith(ContentSecurityPolicyConfiguration.DEFAULT_RULE));
            assertThat(
                    cspHeaders.get(CONTENT_SECURITY_POLICY_HEADER), equalTo(DirectoryBrowserSupport.DEFAULT_CSP_VALUE));
        }
    }

    @SuppressRestrictedWarnings({DirectoryBrowserSupport.class})
    @Test
    public void directoryBrowserSupportWinsOverCspPluginWithEnforcing() throws IOException, SAXException {
        ExtensionList.lookupSingleton(ContentSecurityPolicyConfiguration.class).setReportOnly(false);
        try (JenkinsRule.WebClient wc = j.createWebClient()) {
            final Page htmlPage = wc.goTo("userContent/readme.txt", "text/plain");
            assertThat(htmlPage.getWebResponse().getStatusCode(), is(200));
            final Map<String, String> cspHeaders = getCspResponseHeadersMap(htmlPage.getWebResponse());
            assertThat(cspHeaders.size(), is(DBS_AND_ENFORCING_CSP_HEADERS.size()));
            assertThat(
                    cspHeaders.get(CONTENT_SECURITY_POLICY_HEADER), equalTo(DirectoryBrowserSupport.DEFAULT_CSP_VALUE));
        }
    }

    @Test
    public void directoryBrowserSupportCustomWinsOverCspPluginWithEnforcing() throws IOException, SAXException {
        final String customValue = "foo";
        System.setProperty(DBS_CSP_SYSTEM_PROPERTY, customValue);
        ExtensionList.lookupSingleton(ContentSecurityPolicyConfiguration.class).setReportOnly(false);
        try (JenkinsRule.WebClient wc = j.createWebClient()) {
            final Page htmlPage = wc.goTo("userContent/readme.txt", "text/plain");
            assertThat(htmlPage.getWebResponse().getStatusCode(), is(200));
            final Map<String, String> cspHeaders = getCspResponseHeadersMap(htmlPage.getWebResponse());
            assertThat(cspHeaders.size(), is(DBS_AND_ENFORCING_CSP_HEADERS.size()));
            assertThat(cspHeaders.get(CONTENT_SECURITY_POLICY_HEADER), equalTo(customValue));
        }
    }

    @Test
    public void directoryBrowserSupportDisabledLosesToCspPluginWithEnforcing() throws IOException, SAXException {
        System.setProperty(DBS_CSP_SYSTEM_PROPERTY, "");
        ExtensionList.lookupSingleton(ContentSecurityPolicyConfiguration.class).setReportOnly(false);
        try (JenkinsRule.WebClient wc = j.createWebClient()) {
            final Page htmlPage = wc.goTo("userContent/readme.txt", "text/plain");
            assertThat(htmlPage.getWebResponse().getStatusCode(), is(200));
            final Map<String, String> cspHeaders = getCspResponseHeadersMap(htmlPage.getWebResponse());
            assertThat(cspHeaders.size(), is(1));
            assertThat(
                    cspHeaders.get(CONTENT_SECURITY_POLICY_HEADER),
                    startsWith(ContentSecurityPolicyConfiguration.DEFAULT_RULE));
        }
    }

    @Test
    public void resourceDomainHasNoHeaderWithReporting() throws IOException, SAXException {
        ResourceDomainConfiguration.get().setUrl(j.getURL().toExternalForm().replace("localhost", RRURL_HOSTNAME));
        try (JenkinsRule.WebClient wc = j.createWebClient().withRedirectEnabled(true)) {
            final Page htmlPage = wc.goTo("userContent/readme.txt", "text/plain");
            assertThat(htmlPage.getWebResponse().getStatusCode(), is(200));
            final Map<String, String> cspHeaders = getCspResponseHeadersMap(htmlPage.getWebResponse());
            assertThat(cspHeaders.size(), is(0));
        }
    }

    @Test
    public void resourceDomainHasNoHeaderWithEnforcing() throws IOException, SAXException {
        ResourceDomainConfiguration.get().setUrl(j.getURL().toExternalForm().replace("localhost", RRURL_HOSTNAME));
        ExtensionList.lookupSingleton(ContentSecurityPolicyConfiguration.class).setReportOnly(false);
        try (JenkinsRule.WebClient wc = j.createWebClient().withRedirectEnabled(true)) {
            final Page htmlPage = wc.goTo("userContent/readme.txt", "text/plain");
            assertThat(htmlPage.getWebResponse().getStatusCode(), is(200));
            final Map<String, String> cspHeaders = getCspResponseHeadersMap(htmlPage.getWebResponse());
            assertThat(cspHeaders.size(), is(0));
        }
    }

    private static Map<String, String> getResponseHeadersMap(WebResponse response) {
        return response.getResponseHeaders().stream()
                .map(pair -> Map.entry(pair.getName(), pair.getValue()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    private static Map<String, String> getCspResponseHeadersMap(WebResponse response) {
        return getResponseHeadersMap(response).entrySet().stream()
                .filter(entry -> CSP_HEADERS.contains(entry.getKey()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    // https://github.com/jenkinsci/jenkins/blob/b8e5141a9e69318d908982eaecdfea798010f954/test/src/test/java/jenkins/security/ResourceDomainTest.java#L45-L53
    public static final String RRURL_HOSTNAME = "127.0.0.1";
    private static final String DBS_CSP_SYSTEM_PROPERTY = "hudson.model.DirectoryBrowserSupport.CSP";
    private static final String CONTENT_SECURITY_POLICY_HEADER = "Content-Security-Policy";
    private static final String CONTENT_SECURITY_POLICY_REPORT_ONLY_HEADER = "Content-Security-Policy-Report-Only";
    private static final String X_WEBKIT_CSP_HEADER = "X-WebKit-CSP";
    private static final String X_CONTENT_SECURITY_POLICY_HEADER = "X-Content-Security-Policy";
    private static final List<String> CSP_HEADERS = List.of(
            CONTENT_SECURITY_POLICY_HEADER,
            X_WEBKIT_CSP_HEADER,
            X_CONTENT_SECURITY_POLICY_HEADER,
            CONTENT_SECURITY_POLICY_REPORT_ONLY_HEADER);
    private static final List<String> DBS_AND_ENFORCING_CSP_HEADERS =
            List.of(CONTENT_SECURITY_POLICY_HEADER, X_WEBKIT_CSP_HEADER, X_CONTENT_SECURITY_POLICY_HEADER);
}
