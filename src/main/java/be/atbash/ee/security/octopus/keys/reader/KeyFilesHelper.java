/*
 * Copyright 2017-2018 Rudy De Busscher (https://www.atbash.be)
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

import be.atbash.config.util.ResourceUtils;
import be.atbash.ee.security.octopus.keys.config.JwtSupportConfiguration;
import be.atbash.util.CDIUtils;
import com.google.common.base.Predicate;
import com.google.common.base.Predicates;
import com.google.common.collect.Iterators;
import com.google.common.collect.Sets;
import com.google.common.io.Files;
import org.reflections.Reflections;
import org.reflections.scanners.ResourcesScanner;
import org.reflections.vfs.Vfs;
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

    private final Object LOCK = new Object();

    @Inject
    private Logger logger;

    @Inject
    private JwtSupportConfiguration jwtSupportConfiguration;

    private KeyResourceTypeProvider keyResourceTypeProvider;

    private AtbashResourceScanner scanner;

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
        if (ResourceUtils.resourceExists(keyConfigParameterValue)) {
            if (keyConfigParameterValue.startsWith(ResourceUtils.CLASSPATH_PREFIX)) {
                // File/resource or directory Exists

                performScanning();
                // See if it is a resource on the classpath
                String resourceName = keyConfigParameterValue.substring(ResourceUtils.CLASSPATH_PREFIX.length());

                if (scanner.existsResource(keyConfigParameterValue)) {
                    result.add(keyConfigParameterValue);
                } else {
                    // It is a directory, get everything in (sub)directory.
                    String pattern = resourceName + ".*";
                    Set<String> resources = scanner.getResources(Pattern.compile(pattern));
                    for (String resource : resources) {
                        result.add(ResourceUtils.CLASSPATH_PREFIX + resource);
                    }
                }
            } else {
                // file, URL exists -> OK
                result.add(keyConfigParameterValue);
            }
        } else {
            // Not found, so it can be that it is a directory
            if (keyConfigParameterValue.startsWith(ResourceUtils.FILE_PREFIX)) {
                File file = new File(keyConfigParameterValue.substring(ResourceUtils.FILE_PREFIX.length()));
                if (file.exists() && file.canRead()) {
                    if (file.isDirectory()) {
                        // directory
                        for (File f : Files.fileTreeTraverser().preOrderTraversal(file)) {

                            if (f.isFile()) {
                                result.add(ResourceUtils.FILE_PREFIX + f.getAbsoluteFile().toString());
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
                logger.warn(String.format("(OCT-KEY-012) Unable to determine type of '%s'", path));
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
    }

    private void performScanning() {
        // Make sure we only scan from a single thread.
        if (scanner == null) {
            synchronized (LOCK) {
                if (scanner == null) {

                    // We are using reflection a bit different.
                    //Because I need something like a resourceScanner but which keeps the 'full' path as key in the store and not only the filename.
                    // So I create an instance of a custom scanner and later I ask the resource files fro the store directly.

                    scanner = new AtbashResourceScanner();
                    new Reflections("", scanner);
                }
            }
        }
    }

    private static class AtbashResourceScanner extends ResourcesScanner {
        AtbashResourceScanner() {
            // Otherwise all classes are also accepted.
            setResultFilter(Predicates.<String>alwaysFalse());
        }

        @Override
        public Object scan(Vfs.File file, Object classObject) {
            this.getStore().put(file.getRelativePath(), file.getRelativePath());
            return classObject;
        }

        public Set<String> getResources(final Pattern pattern) {
            Predicate<String> predicate = new Predicate<String>() {
                public boolean apply(String input) {
                    return pattern.matcher(input).matches();
                }
            };
            return Sets.newHashSet(Iterators.filter(getStore().keySet().iterator(), predicate));
        }

        public boolean existsResource(String resourceName) {
            return getStore().keySet().contains(resourceName);
        }
    }
}
