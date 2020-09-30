package io.snyk.integrations.fortify.parser;

import java.util.Date;

public class Scan {
    public Date scanDate;

    public String displayTargetFile;
    
    public Issue[] vulnerabilities;

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
    }
}