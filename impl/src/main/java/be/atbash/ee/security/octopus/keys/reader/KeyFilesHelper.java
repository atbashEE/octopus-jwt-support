/*
 * Copyright 2017-2019 Rudy De Busscher (https://www.atbash.be)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package be.atbash.ee.security.octopus.keys.reader;

import be.atbash.ee.security.octopus.config.JwtSupportConfiguration;
import be.atbash.util.CDIUtils;
import be.atbash.util.resource.ResourceScanner;
import be.atbash.util.resource.ResourceUtil;
import org.slf4j.Logger;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Helps to identify all the key files when directory defined (resource or file system)
 */
@ApplicationScoped
public class KeyFilesHelper {

    @Inject
    private Logger logger;

    @Inject
    private JwtSupportConfiguration jwtSupportConfiguration;

    @Inject
    private ResourceUtil resourceUtil;

    private KeyResourceTypeProvider keyResourceTypeProvider;

    private ResourceScanner scanner;

    @PostConstruct
    public void init() {
        keyResourceTypeProvider = CDIUtils.retrieveOptionalInstance(KeyResourceTypeProvider.class);
        // No developer defined CDI instance, use the config defined one (is the default if not specified).
        if (keyResourceTypeProvider == null) {
            keyResourceTypeProvider = jwtSupportConfiguration.getKeyResourceTypeProvider();
        }
    }

    public List<String> determineKeyFiles(String keyConfigParameterValue) {
        checkDependencies();
        List<String> result = new ArrayList<>();
        if (resourceUtil.resourceExists(keyConfigParameterValue)) {
            if (keyConfigParameterValue.startsWith(ResourceUtil.CLASSPATH_PREFIX)) {
                // File/resource or directory Exists

                performScanning();
                // See if it is a resource on the classpath
                String resourceName = keyConfigParameterValue.substring(ResourceUtil.CLASSPATH_PREFIX.length());

                if (scanner.existsResource(resourceName)) {
                    result.add(keyConfigParameterValue);
                } else {
                    // It is a directory, get everything in (sub)directory.
                    String pattern = resourceName + ".*";
                    Set<String> resources = scanner.getResources(Pattern.compile(pattern));
                    for (String resource : resources) {
                        result.add(ResourceUtil.CLASSPATH_PREFIX + resource);
                    }
                }
            } else {
                // file, URL exists -> OK
                result.add(keyConfigParameterValue);
            }
        } else {
            // Not found, so it can be that it is a directory
            if (keyConfigParameterValue.startsWith(ResourceUtil.FILE_PREFIX)) {
                File file = new File(keyConfigParameterValue.substring(ResourceUtil.FILE_PREFIX.length()));
                if (file.exists() && file.canRead()) {
                    if (file.isDirectory()) {
                        // directory

                        for (File f : defineFiles(file)) {

                            if (f.isFile()) {
                                result.add(ResourceUtil.FILE_PREFIX + f.getAbsoluteFile().toString());
                            }
                        }
                    }
                }
            }

        }

        Iterator<String> iterator = result.iterator();
        while (iterator.hasNext()) {
            String path = iterator.next();
            if (keyResourceTypeProvider.determineKeyResourceType(path) == null) {
                // When file isn't matched to any of the types -> remove from list
                iterator.remove();
                if (logger.isWarnEnabled()) {
                    logger.warn(String.format("(OCT-KEY-012) Unable to determine type of '%s'", path));
                }
            }
        }
        return result;
    }

    private List<File> defineFiles(File file) {
        List<File> result = new ArrayList<>();
        File[] files = file.listFiles();
        if (files == null) {
            return result;
        }
        for (File f : files) {
            if (f.isDirectory()) {
                result.addAll(defineFiles(f));
            } else {
                result.add(f);
            }
        }
        return result;
    }

    private void checkDependencies() {
        // Duplicated within KeyReader
        // for the JAVA SE Case
        if (keyResourceTypeProvider == null) {
            jwtSupportConfiguration = JwtSupportConfiguration.getInstance();
            keyResourceTypeProvider = jwtSupportConfiguration.getKeyResourceTypeProvider();
        }

        if (resourceUtil == null) {
            resourceUtil = ResourceUtil.getInstance();
        }
    }

    private synchronized void performScanning() {
        // Make sure we only scan from a single thread.
        if (scanner == null) {
            scanner = ResourceScanner.getInstance();
        }
    }
}
