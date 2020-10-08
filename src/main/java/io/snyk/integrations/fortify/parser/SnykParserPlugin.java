package io.snyk.integrations.fortify.parser;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.UUID;
import java.util.Date;
import java.text.DateFormat;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fortify.plugin.api.ScanBuilder;
import com.fortify.plugin.api.ScanData;
import com.fortify.plugin.api.ScanParsingException;
import com.fortify.plugin.api.StaticVulnerabilityBuilder;
import com.fortify.plugin.api.VulnerabilityHandler;
import com.fortify.plugin.spi.ParserPlugin;

public class SnykParserPlugin implements ParserPlugin<CustomAttribute> {
    private static final Logger LOG = LoggerFactory.getLogger(SnykParserPlugin.class);
    private static final Gson gson = new GsonBuilder().setDateFormat(DateFormat.FULL, DateFormat.FULL).create();

    @Override
    public void start() throws Exception {
        LOG.info("SnykParserPlugin plugin is starting");
    }

    @Override
    public void stop() throws Exception {
        LOG.info("SnykParserPlugin plugin is stopping");
    }

    @Override
    public Class<CustomAttribute> getVulnerabilityAttributesClass() {
        return CustomAttribute.class;
    }

    @Override
    public void parseScan(final ScanData scanData, final ScanBuilder scanBuilder)
            throws ScanParsingException, IOException {
        try {
            Scan[] scans = parseJson(scanData);

            buildScanObject(scanBuilder, scans);

        } catch (NullPointerException e) {
            throw new ScanParsingException("Parsing error: requried field not found", e);
        } finally {
            scanBuilder.completeScan();
        }
    }

    private void buildScanObject(final ScanBuilder scanBuilder, final Scan[] scans) {
        String uniqueId = hashJsonObject(scans);

        scanBuilder.setGuid(uniqueId);
        scanBuilder.setScanDate(scans.length > 0 && scans[0].scanDate != null ? scans[0].scanDate : new Date());
    }

    @Override
    public void parseVulnerabilities(final ScanData scanData, final VulnerabilityHandler vulnerabilityHandler)
            throws ScanParsingException, IOException {
        try {
            Scan[] scans = parseJson(scanData);

            for (Scan scan : scans) {
                for (Scan.Issue issue : scan.vulnerabilities) {
                    try {
                        String targetFile = scan.targetFile != null ? scan.targetFile : scan.displayTargetFile;
                        String uniqueId = hashStringObject(targetFile) + ":" + hashJsonObject(issue);
                        StaticVulnerabilityBuilder vulnerabilityBuilder = vulnerabilityHandler
                                .startStaticVulnerability(uniqueId);

                        buildVulnerability(vulnerabilityBuilder, issue, targetFile, scan.projectName);

                        vulnerabilityBuilder.completeVulnerability();
                    } catch (NullPointerException e) {
                        LOG.error("Error when processing vuln (missing field?). Continuing to next one");
                    }
                }
            }
        } catch (NullPointerException e) {
            throw new ScanParsingException("Parsing error: requried field not found", e);
        }
    }

    private void buildVulnerability(final StaticVulnerabilityBuilder vulnerabilityBuilder, final Scan.Issue issue, final String targetFile, final String projectName) {
        // mandatory by SSC
        vulnerabilityBuilder.setAccuracy(5f);
        vulnerabilityBuilder.setAnalyzer("snyk");
        vulnerabilityBuilder.setEngineType("SNYK_ENGINE");
        vulnerabilityBuilder.setConfidence(5f);

        switch (issue.severity) {
            case "high":
                vulnerabilityBuilder.setPriority(StaticVulnerabilityBuilder.Priority.High);
                break;
            case "medium":
                vulnerabilityBuilder.setPriority(StaticVulnerabilityBuilder.Priority.Medium);
                break;
            case "low":
                vulnerabilityBuilder.setPriority(StaticVulnerabilityBuilder.Priority.Low);
                break;
            default:
                vulnerabilityBuilder.setPriority(StaticVulnerabilityBuilder.Priority.Critical);
                break;
        }

        vulnerabilityBuilder.setImpact(5f);
        vulnerabilityBuilder.setProbability(5f);
        vulnerabilityBuilder.setCategory(issue.title);

        vulnerabilityBuilder.setFileName(issue.from[issue.from.length - 1]);

        // custom
        vulnerabilityBuilder.setStringCustomAttributeValue(CustomAttribute.SNYK_ID, issue.id);
        vulnerabilityBuilder.setStringCustomAttributeValue(CustomAttribute.TITLE, issue.title);
        vulnerabilityBuilder.setStringCustomAttributeValue(CustomAttribute.NAME, issue.name);
        vulnerabilityBuilder.setStringCustomAttributeValue(CustomAttribute.VERSION, issue.version);
        vulnerabilityBuilder.setStringCustomAttributeValue(CustomAttribute.DESCRIPTION, issue.description);
        vulnerabilityBuilder.setStringCustomAttributeValue(CustomAttribute.SEVERITY, issue.severity);
        vulnerabilityBuilder.setStringCustomAttributeValue(CustomAttribute.LANGUAGE, issue.language);
        vulnerabilityBuilder.setStringCustomAttributeValue(CustomAttribute.PACKAGE_MANAGER, issue.packageManager);
        vulnerabilityBuilder.setDateCustomAttributeValue(CustomAttribute.PUBLICATION_DATE, issue.publicationTime);
        vulnerabilityBuilder.setStringCustomAttributeValue(CustomAttribute.FROM, String.join(" > ", issue.from));
        vulnerabilityBuilder.setStringCustomAttributeValue(CustomAttribute.IS_UPGRADABLE,
                (issue.isUpgradable ? "Yes" : "No"));
        vulnerabilityBuilder.setStringCustomAttributeValue(CustomAttribute.IS_PATCHABLE,
                (issue.isPatchable ? "Yes" : "No"));
        vulnerabilityBuilder.setStringCustomAttributeValue(CustomAttribute.TARGET_FILE, targetFile);
        vulnerabilityBuilder.setStringCustomAttributeValue(CustomAttribute.PROJECT_NAME, projectName);
        vulnerabilityBuilder.setStringCustomAttributeValue(CustomAttribute.ISSUE_URL,
                "https://snyk.io/vuln/" + issue.id);
    }

    private Scan[] parseJson(final ScanData scanData) throws IOException {
        try (final InputStream is = scanData.getInputStream(x -> x.endsWith(".json"))) {
            final JsonReader json = new JsonReader(new InputStreamReader(is));
            /*
             * snyk test --all-sub-projects (that starts with [ and not {) [ {
             * "vulnerabilities": [], "ok": true, "dependencyCount": 0, ....
             */
            if (json.peek() == JsonToken.BEGIN_ARRAY) {
                return gson.fromJson(json, Scan[].class);
            } else {
                Scan ret[] = { gson.fromJson(json, Scan.class) };
                return ret;
            }
        }
    }

    private String hashJsonObject(final Object obj) {
        try {
            byte[] jsonStringBytes = gson.toJson(obj).getBytes();
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(jsonStringBytes);
            return UUID.nameUUIDFromBytes(digest).toString();
        } catch (NoSuchAlgorithmException e) {
            return ""; // should never reach here
        }
    }

    private String hashStringObject(final String obj) {
        try {
            byte[] stringBytes = obj.getBytes();
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(stringBytes);
            return UUID.nameUUIDFromBytes(digest).toString();
        } catch (NoSuchAlgorithmException e) {
            return ""; // should never reach here
        }
    }
}