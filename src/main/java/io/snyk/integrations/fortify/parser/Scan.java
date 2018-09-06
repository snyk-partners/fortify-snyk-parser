package io.snyk.integrations.fortify.parser;

import java.util.Date;

public class Scan {
    public Date scanDate;
    
    public Issue[] vulnerabilities;

    // ignored
    // public boolean ok;
    // public String packageManager;
    // public String policy;
    // public String summary;
    // public int uniqueCount;
    // public String path;
    // public int dependencyCount;
    // public String org;
    // public ? licensesPolicy;
    // public boolean isPrivate;
    // public ? ignoreSettings;
    // public Filtered filtered;
    // public boolean filesystemPolicy;

    // public class Filtered {
    //     public String[] ignore;
    //     public String[] patch;
    // };

    public class Issue {
        public String id;
        public String title;
        public String name;
        public String version;
        public String description;
        public String severity;
        public String language;
        public String packageManager;
        public Date publicationTime;
        public String[] from;

        public boolean isUpgradable;
        public boolean isPatchable;
        public String __filename;
        // ignored
        // public String packageName;
        // public Semver semver;
        // public ?[] upgradePath;
        // public String creationTime;
        // public String parentDepType;

        // vulnerability only
        // public double cvssScore;
        // public String CVSSv3;
        // public String[] credit;
        // public String moduleName;
        // public String modificationTime;
        // public String disclosureTime;
        // public String[] alternativeIds;
        // public Patch[] patches;
        // public ?[] identifiers

        // license only
        // public String license;
        // public String type;
        // public String licenseTemplateUrl;

        // public class Semver {
        //     public String[] vulnerable;
        //     public String[] unaffected;
        // }

        // public class Patch {
        //     public String[] urls;
        //     public String vestions;
        //     public String modificationTime;
        //     public String[] comments;
        //     public String id;
        // }
    }
}