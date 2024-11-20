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

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.PluginManager;
import hudson.PluginWrapper;
import hudson.model.ManagementLink;
import hudson.model.PeriodicWork;
import hudson.model.User;
import java.util.Date;
import jenkins.model.Jenkins;
import jenkins.util.SystemProperties;
import net.sf.json.JSONObject;
import org.jenkinsci.Symbol;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.StaplerProxy;
import org.kohsuke.stapler.interceptor.RequirePOST;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

@Extension
@Restricted(NoExternalUse.class)
@Symbol("contentSecurityPolicyManagementLink")
public class ContentSecurityPolicyManagementLink extends ManagementLink implements StaplerProxy, ContentSecurityPolicyReceiver {
    public static final Logger LOGGER = Logger.getLogger(ManagementLink.class.getName());

    public static final int ROTATE_PERIOD_HOURS = SystemProperties.getInteger(ContentSecurityPolicyManagementLink.class.getName() + ".ROTATE_PERIOD_HOURS", 6);
    private static /* non-final for Groovy */ int ROTATE_AFTER_HOURS = SystemProperties.getInteger(ContentSecurityPolicyManagementLink.class.getName() + ".ROTATE_AFTER_HOURS", 24);

    private final List<Record> records = new LinkedList<>();

    @Override
    public String getIconFileName() {
        return "document.png";
    }

    @Override
    public String getDisplayName() {
        return "Content Security Policy Report"; // TODO i18n
    }

    @Override
    public String getUrlName() {
        return "content-security-policy-reports";
    }

    @Override
    public String getDescription() {
        return "Review reported Content-Security-Policy violations."; // TODO i18n
    }

    @NonNull
    @Override
    public Category getCategory() {
        return Category.SECURITY;
    }

    @Override
    public Object getTarget() {
        Jenkins.get().checkPermission(getRequiredPermission());
        return this;
    }

    @Override
    public void report(@NonNull ViewContext viewContext, @CheckForNull User user, @NonNull JSONObject report) {
        final JSONObject cspReport = report.getJSONObject("csp-report");
        final String violatedDirective = cspReport.optString("violated-directive", "<UNKNOWN>");
        final String blockedUri = cspReport.optString("blocked-uri", "<UNKNOWN>");
        final String scriptSample = cspReport.optString("script-sample", "<UNKNOWN>");
        Record record = new Record(viewContext.getClassName(), viewContext.getViewName(), violatedDirective, blockedUri, scriptSample, Instant.now(), user == null ? null : user.getId());
        synchronized (records) {
            records.add(record);
        }
    }

    public List<Record> getRecords() {
        synchronized (records) {
            return new ArrayList<>(records);
        }
    }

    @RequirePOST
    public HttpResponse doClear() {
        synchronized (this.records) {
            this.records.clear();
        }
        return HttpResponses.forwardToPreviousPage();
    }

    public void rotate() {
        synchronized (this.records) {
            this.records.removeIf(r -> r.getTime().isBefore(Instant.now().minus(ROTATE_AFTER_HOURS, ChronoUnit.HOURS)));
        }
    }

    @Extension
    public static class Rotator extends PeriodicWork {
        @Override
        public long getRecurrencePeriod() {
            return TimeUnit.HOURS.toMillis(ROTATE_PERIOD_HOURS);
        }

        @Override
        protected void doRun() throws Exception {
            ExtensionList.lookupSingleton(ContentSecurityPolicyManagementLink.class).rotate();
        }
    }

    public static final class Record {
        private final String contextClassName;
        private final String contextViewName;
        private final String violatedDirective;
        private final String blockedUri;
        private final String scriptSample;
        private final Instant time;
        private final String username;

        public Record(String contextClassName, String contextViewName, String violatedDirective, String blockedUri, String scriptSample, Instant time, String username) {
            this.violatedDirective = violatedDirective;
            this.contextClassName = contextClassName;
            this.contextViewName = contextViewName;
            this.blockedUri = blockedUri;
            this.scriptSample = scriptSample;
            this.time = time;
            this.username = username;
        }

        public String getContextClassName() {
            return contextClassName;
        }

        public String getContextViewName() {
            return contextViewName;
        }

        public String getViolatedDirective() {
            return violatedDirective;
        }

        public String getBlockedUri() {
            return blockedUri;
        }

        public String getScriptSample() {
            return scriptSample;
        }

        public Instant getTime() {
            return time;
        }

        public Date getDate() {
            return Date.from(time);
        }

        public String getUsername() {
            return username;
        }

        public PluginWrapper getContextPlugin() {
            try {
                final PluginManager pluginManager = Jenkins.get().getPluginManager();
                return pluginManager.whichPlugin(pluginManager.uberClassLoader.loadClass(this.contextClassName));
            } catch (ClassNotFoundException e) {
                LOGGER.log(Level.FINE, e, () -> "Failed to determine plugin for class: " + contextClassName);
            }
            return null;
        }

        public User getUser() {
            if (username == null) {
                return null;
            }
            return User.get(username, false, Collections.emptyMap());
        }
    }
}
