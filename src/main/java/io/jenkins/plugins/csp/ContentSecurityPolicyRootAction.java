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
import hudson.ExtensionList;
import hudson.model.InvisibleAction;
import hudson.model.UnprotectedRootAction;
import hudson.model.User;
import hudson.security.csrf.CrumbExclusion;
import hudson.util.HttpResponses;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.sf.json.JSONObject;
import org.apache.commons.io.IOUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest2;
import org.springframework.security.core.Authentication;

import java.io.IOException;
import java.io.Reader;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.kohsuke.stapler.verb.POST;

/**
 * Reporting endpoint for CSP violations.
 * {@link StaplerRequest2#getRestOfPath()} is used to associate violations with
 * the view they occur in; {@link ContentSecurityPolicyDecorator} needs to have a dynamic report
 * URL for that.
 * <p>
 * While this is an {@link hudson.model.UnprotectedRootAction}, only submissions with correct HMAC
 * from {@link Context#encodeContext(Object, Authentication, String)} will be accepted.
 */
@Extension
@Restricted(NoExternalUse.class)
@Symbol("contentSecurityPolicyRootAction")
public class ContentSecurityPolicyRootAction extends InvisibleAction implements UnprotectedRootAction {

    public static final String URL = "content-security-policy-reporting-endpoint";
    public static final Logger LOGGER = Logger.getLogger(ContentSecurityPolicyRootAction.class.getName());

    @Override
    public String getUrlName() {
        return URL;
    }

    @SuppressWarnings("lgtm[jenkins/no-permission-check]")
    @POST
    public HttpResponse doDynamic(StaplerRequest2 req) {
        final String requestRestOfPath = req.getRestOfPath();
        String restOfPath = requestRestOfPath.startsWith("/") ? requestRestOfPath.substring(1) : requestRestOfPath;

        try {
            final Context.DecodedContext context = Context.decodeContext(restOfPath);

            ContentSecurityPolicyReceiver.ViewContext viewContext = new ContentSecurityPolicyReceiver.ViewContext(context.contextClassName, context.restOfPath);
            try (Reader reader = req.getReader()) {
                String report = IOUtils.toString(reader); // TODO Limit max length to 1MB or so even though at this point we know the user is legitimate
                LOGGER.log(Level.FINE, () -> viewContext + " " + report);
                final JSONObject jsonObject = JSONObject.fromObject(report);
                for (ContentSecurityPolicyReceiver receiver : ExtensionList.lookup(ContentSecurityPolicyReceiver.class)) {
                    try {
                        final User user = context.userId == null ? null : User.getById(context.userId, false);
                        receiver.report(viewContext, user, jsonObject);
                    } catch (Exception ex) {
                        LOGGER.log(Level.WARNING, ex, () -> "Error reporting CSP to " + receiver);
                    }
                }
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, e, () -> "Failed to read request body for /" + URL + "/" + restOfPath);
            }
            return HttpResponses.ok();
        } catch (RuntimeException ex) {
            LOGGER.log(Level.FINE, "Unexpected rest of path failed to decode: " + restOfPath + " with exception: " + ex.getMessage());
            return HttpResponses.ok();
        }
    }

    @Extension
    public static class CrumbExclusionImpl extends CrumbExclusion {
        @Override
        public boolean process(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
            String pathInfo = request.getPathInfo();
            if (pathInfo != null && pathInfo.startsWith("/" + URL + "/")) {
                chain.doFilter(request, response);
                return true;
            }
            return false;
        }
    }
}
