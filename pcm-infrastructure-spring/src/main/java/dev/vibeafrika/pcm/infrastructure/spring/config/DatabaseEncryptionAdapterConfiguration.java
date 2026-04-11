package dev.vibeafrika.pcm.infrastructure.spring.config;

import dev.vibeafrika.pcm.consent.infrastructure.persistence.listener.ConsentEncryptionEntityListener;
import dev.vibeafrika.pcm.domain.encryption.BoundedContext;
import dev.vibeafrika.pcm.domain.encryption.IEncryptionService;
import dev.vibeafrika.pcm.infrastructure.encryption.BlindIndexService;
import dev.vibeafrika.pcm.infrastructure.encryption.adapter.DatabaseEncryptionAdapter;
import dev.vibeafrika.pcm.infrastructure.encryption.adapter.EncryptionEntityListener;
import dev.vibeafrika.pcm.preference.infrastructure.persistence.listener.PreferenceEncryptionEntityListener;
import dev.vibeafrika.pcm.profile.infrastructure.persistence.listener.ProfileEncryptionEntityListener;
import dev.vibeafrika.pcm.segment.infrastructure.persistence.listener.SegmentEncryptionEntityListener;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring configuration for the database encryption adapter.
 *
 * <p>Wires the {@link DatabaseEncryptionAdapter} and registers the
 * {@link EncryptionEntityListener} as a Spring-managed bean so that
 * JPA can inject the adapter into listener instances via the static setter.
 *
 * <p>The default bounded context for encryption operations is configurable
 * via {@code encryption.default-context} (defaults to {@code PROFILE}).
 * Each bounded context can override this by providing its own adapter bean.
 */
@Configuration
public class DatabaseEncryptionAdapterConfiguration {

    @Value("${encryption.default-context:PROFILE}")
    private String defaultContextName;

    /**
     * Creates the {@link DatabaseEncryptionAdapter} bean.
     *
     * @param encryptionService the encryption service for field-level encryption
     * @param blindIndexService the blind index service for searchable fields
     * @return the configured adapter
     */
    @Bean
    @ConditionalOnBean({IEncryptionService.class, BlindIndexService.class})
    public DatabaseEncryptionAdapter databaseEncryptionAdapter(
            IEncryptionService encryptionService,
            BlindIndexService blindIndexService) {
        BoundedContext context;
        try {
            context = BoundedContext.valueOf(defaultContextName.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "Invalid encryption.default-context value: '" + defaultContextName +
                    "'. Must be one of: PROFILE, CONSENT, SEGMENT, PREFERENCE", e);
        }
        DatabaseEncryptionAdapter adapter =
                new DatabaseEncryptionAdapter(encryptionService, blindIndexService, context);

        // Wire the Profile bounded context entity listener
        ProfileEncryptionEntityListener.setDelegates(
                adapter::encryptEntity,
                adapter::decryptEntity);

        return adapter;
    }

    /**
     * Creates the {@link DatabaseEncryptionAdapter} bean for the Consent bounded context.
     *
     * <p>Wires the {@link ConsentEncryptionEntityListener} static delegates so that
     * JPA lifecycle callbacks transparently encrypt/decrypt Consent entities.
     *
     * @param encryptionService the encryption service for field-level encryption
     * @param blindIndexService the blind index service for searchable fields
     * @return the configured adapter for the CONSENT bounded context
     */
    @Bean("consentDatabaseEncryptionAdapter")
    @ConditionalOnBean({IEncryptionService.class, BlindIndexService.class})
    public DatabaseEncryptionAdapter consentDatabaseEncryptionAdapter(
            IEncryptionService encryptionService,
            BlindIndexService blindIndexService) {
        DatabaseEncryptionAdapter adapter =
                new DatabaseEncryptionAdapter(encryptionService, blindIndexService, BoundedContext.CONSENT);

        // Wire the Consent bounded context entity listener
        ConsentEncryptionEntityListener.setDelegates(
                adapter::encryptEntity,
                adapter::decryptEntity);

        return adapter;
    }

    /**
     * Creates the {@link DatabaseEncryptionAdapter} bean for the Segment bounded context.
     *
     * <p>Wires the {@link SegmentEncryptionEntityListener} static delegates so that
     * JPA lifecycle callbacks transparently encrypt/decrypt Segment entities.
     *
     * @param encryptionService the encryption service for field-level encryption
     * @param blindIndexService the blind index service for searchable fields
     * @return the configured adapter for the SEGMENT bounded context
     */
    @Bean("segmentDatabaseEncryptionAdapter")
    @ConditionalOnBean({IEncryptionService.class, BlindIndexService.class})
    public DatabaseEncryptionAdapter segmentDatabaseEncryptionAdapter(
            IEncryptionService encryptionService,
            BlindIndexService blindIndexService) {
        DatabaseEncryptionAdapter adapter =
                new DatabaseEncryptionAdapter(encryptionService, blindIndexService, BoundedContext.SEGMENT);

        // Wire the Segment bounded context entity listener
        SegmentEncryptionEntityListener.setDelegates(
                adapter::encryptEntity,
                adapter::decryptEntity);

        return adapter;
    }

    /**
     * Creates the {@link DatabaseEncryptionAdapter} bean for the Preference bounded context.
     *
     * <p>Wires the {@link PreferenceEncryptionEntityListener} static delegates so that
     * JPA lifecycle callbacks transparently encrypt/decrypt Preference entities.
     *
     * @param encryptionService the encryption service for field-level encryption
     * @param blindIndexService the blind index service for searchable fields
     * @return the configured adapter for the PREFERENCE bounded context
     */
    @Bean("preferenceDatabaseEncryptionAdapter")
    @ConditionalOnBean({IEncryptionService.class, BlindIndexService.class})
    public DatabaseEncryptionAdapter preferenceDatabaseEncryptionAdapter(
            IEncryptionService encryptionService,
            BlindIndexService blindIndexService) {
        DatabaseEncryptionAdapter adapter =
                new DatabaseEncryptionAdapter(encryptionService, blindIndexService, BoundedContext.PREFERENCE);

        // Wire the Preference bounded context entity listener
        PreferenceEncryptionEntityListener.setDelegates(
                adapter::encryptEntity,
                adapter::decryptEntity);

        return adapter;
    }

    /**
     * Registers the {@link EncryptionEntityListener} as a Spring bean.
     *
     * <p>Spring will inject the {@link DatabaseEncryptionAdapter} into the
     * listener via the {@link EncryptionEntityListener#setAdapter(DatabaseEncryptionAdapter)}
     * method, making it available to all JPA entity listener instances.
     *
     * @return the entity listener
     */
    @Bean
    public EncryptionEntityListener encryptionEntityListener() {
        return new EncryptionEntityListener();
    }
}
