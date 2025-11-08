package io.jenkins.plugins.csp.rules;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import io.jenkins.plugins.csp.CustomRule;
import io.jenkins.plugins.csp.CustomRuleDescriptor;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import jenkins.model.Jenkins;
import jenkins.security.csp.CspBuilder;
import jenkins.security.csp.Decorator;
import jenkins.security.csp.FetchDirective;
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
        FetchDirective.toFetchDirective(directive).ifPresent(fd -> {
            builder.remove(directive);
            if (isDisableInheritance()) {
                builder.initialize(fd);
            }
        });
    }

    public boolean isDisableInheritance() {
        return disableInheritance;
    }

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
            return model;
        }

        public FormValidation doCheckDirective(
                @QueryParameter String value, @QueryParameter boolean disableInheritance) {
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
                            return FormValidation.warning("Resetting " + fd.toKey()
                                    + " to 'none' is discouraged. The Jenkins UI may break unless you're careful. If this happens, you can restart Jenkins with the Java system property '"
                                    + Decorator.class.getName()
                                    + ".headerName' set to 'Content-Security-Policy-Report-Only' to recover.");
                        }
                        if (disableInheritance && fd.getFallback() != null) {
                            /* We need to check connect-src here, because it's required for AJAX behavior, but is undefined by default */
                            if (List.of(FetchDirective.STYLE_SRC, FetchDirective.SCRIPT_SRC)
                                            .contains(fd.getFallback())
                                    || Objects.equals(FetchDirective.CONNECT_SRC, fd)) {
                                return FormValidation.warning("Resetting " + fd.toKey()
                                        + " to 'none' with disabled inheritance is discouraged. The Jenkins UI may break unless you're careful. If this happens, you can restart Jenkins with the Java system property '"
                                        + Decorator.class.getName()
                                        + ".headerName' set to 'Content-Security-Policy-Report-Only' to recover.");
                            }
                        }
                        return FormValidation.ok();
                    })
                    .orElse(FormValidation.ok());
        }
    }
}
