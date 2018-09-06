package io.snyk.integrations.fortify.parser;

public enum CustomAttribute implements com.fortify.plugin.spi.VulnerabilityAttribute {
    
    SNYK_ID("snykId", AttrType.STRING),
    TITLE("title", AttrType.STRING),
    NAME("name", AttrType.STRING),
    VERSION("version", AttrType.STRING),
    DESCRIPTION("description", AttrType.LONG_STRING),
    SEVERITY("severity", AttrType.STRING),
    LANGUAGE("language", AttrType.STRING),
    PACKAGE_MANAGER("packageManager", AttrType.STRING),
    PUBLICATION_DATE("publicationTime", AttrType.DATE),
    FROM("from", AttrType.STRING),
    IS_UPGRADABLE("isUpgradable", AttrType.STRING),
    IS_PATCHABLE("isPatchable", AttrType.STRING),
    FILENAME("filename", AttrType.STRING),
    ISSUE_URL("issueUrl", AttrType.STRING);
    ;

    private final String name;
    private final AttrType type;

    CustomAttribute(String name, AttrType type) {
        this.name = name;
        this.type = type;
    }

    @Override
    public String attributeName() {
        return name;
    }

    @Override
    public AttrType attributeType() {
        return type;
    }
}