package io.jenkins.plugins.csp;

import hudson.ExtensionPoint;
import hudson.model.Describable;
import jenkins.security.csp.CspBuilder;

public abstract class CustomRule implements Describable<CustomRule>, ExtensionPoint {
    public void apply(CspBuilder builder) {}
}
