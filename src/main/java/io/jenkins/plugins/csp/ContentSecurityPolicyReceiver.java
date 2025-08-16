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
import hudson.ExtensionPoint;
import hudson.model.User;
import java.util.Objects;
import net.sf.json.JSONObject;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

/**
 * Extension point for receivers of Content Security Policy reports.
 */
@Restricted(NoExternalUse.class)
public interface ContentSecurityPolicyReceiver extends ExtensionPoint {
    void report(@NonNull ViewContext viewContext, @CheckForNull User user, @NonNull JSONObject report);

    class ViewContext {
        private final String className;
        private final String viewName;

        public ViewContext(@NonNull String className, @NonNull String viewName) {
            this.className = Objects.requireNonNull(className, "className");
            this.viewName = Objects.requireNonNull(viewName, "viewName");
        }

        @NonNull
        public String getViewName() {
            return viewName;
        }

        @NonNull
        public String getClassName() {
            return className;
        }

        @Override
        public String toString() {
            return "Context{" + "className='" + className + '\'' + ", viewName='" + viewName + '\'' + '}';
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            ViewContext viewContext = (ViewContext) o;
            return className.equals(viewContext.className) && viewName.equals(viewContext.viewName);
        }

        @Override
        public int hashCode() {
            return Objects.hash(className, viewName);
        }
    }
}
