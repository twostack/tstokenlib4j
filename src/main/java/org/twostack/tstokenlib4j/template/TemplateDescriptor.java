package org.twostack.tstokenlib4j.template;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * POJO representing a JSON script template loaded from the classpath.
 *
 * <p>Each template contains a hex string with {@code {{placeholder}}} markers
 * that lock builders substitute with encoded parameter values. The {@code name},
 * {@code version}, and {@code format} fields provide metadata about the template.
 *
 * <p>Uses {@code @JsonIgnoreProperties(ignoreUnknown = true)} to remain
 * forward-compatible with template fields not consumed by the Java library
 * (such as {@code parameters}, {@code description}, {@code category}, and {@code metadata}).
 *
 * @see TemplateLoader
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class TemplateDescriptor {

    private String name;
    private String version;
    private String hex;
    private String format;

    public TemplateDescriptor() {
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getHex() {
        return hex;
    }

    public void setHex(String hex) {
        this.hex = hex;
    }

    public String getFormat() {
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }
}
