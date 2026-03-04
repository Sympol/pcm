package dev.vibeafrika.pcm.infrastructure.spring;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.transaction.annotation.EnableTransactionManagement;

/**
 * Unified Spring Boot application for PCM modular monolith.
 * Serves all bounded contexts (Preference, Profile, Consent, Segment).
 */
@SpringBootApplication(scanBasePackages = {
    "dev.vibeafrika.pcm.infrastructure.spring",
    "dev.vibeafrika.pcm.preference.infrastructure",
    "dev.vibeafrika.pcm.profile.infrastructure",
    "dev.vibeafrika.pcm.consent.infrastructure",
    "dev.vibeafrika.pcm.segment.infrastructure"
})
@EnableTransactionManagement
@EnableJpaAuditing
public class PcmApplication {

    public static void main(String[] args) {
        SpringApplication.run(PcmApplication.class, args);
    }
}
