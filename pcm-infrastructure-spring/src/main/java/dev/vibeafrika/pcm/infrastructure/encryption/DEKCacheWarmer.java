package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.BoundedContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;

/**
 * Warms the DEK cache on application startup by pre-fetching the active DEK
 * for every {@link BoundedContext}.
 *
 * <p>Warming failures are logged but never propagate — the application must
 * start successfully even when KMS is temporarily unavailable.
 *
 * <p>Satisfies Requirements 10.5 and 10.6.
 */
public class DEKCacheWarmer implements ApplicationListener<ApplicationReadyEvent> {

    private static final Logger logger = LoggerFactory.getLogger(DEKCacheWarmer.class);

    private final KeyManager keyManager;

    public DEKCacheWarmer(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        logger.info("Starting DEK cache warming for all bounded contexts");
        int warmed = 0;
        for (BoundedContext context : BoundedContext.values()) {
            try {
                var result = keyManager.getActiveDEK(context);
                if (result.isSuccess()) {
                    logger.info("DEK cache warmed for context: {}", context);
                    warmed++;
                } else {
                    String reason = result.getError()
                            .map(e -> e.getCode() + ": " + e.getMessage())
                            .orElse("unknown");
                    logger.warn("DEK cache warming skipped for context {}: {}", context, reason);
                }
            } catch (Exception ex) {
                // Never fail startup due to cache warming errors
                logger.warn("DEK cache warming failed for context {}: {}", context, ex.getMessage(), ex);
            }
        }
        logger.info("DEK cache warming complete: {}/{} contexts warmed", warmed, BoundedContext.values().length);
    }
}
