/**
 * JSON template loading and caching for script hex generation.
 *
 * <p>Script templates are JSON files on the classpath containing hex strings with
 * {@code {{placeholder}}} markers. Lock builders load templates via
 * {@link org.twostack.tstokenlib4j.template.TemplateLoader} and substitute
 * parameter values to produce the final script hex.
 *
 * @see org.twostack.tstokenlib4j.template.TemplateLoader
 * @see org.twostack.tstokenlib4j.template.TemplateDescriptor
 */
package org.twostack.tstokenlib4j.template;
