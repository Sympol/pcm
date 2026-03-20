package dev.vibeafrika.pcm.infrastructure.spring.config;

import org.springframework.aop.framework.autoproxy.BeanNameAutoProxyCreator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.interceptor.TransactionInterceptor;

import java.util.Properties;

/**
 * Transaction configuration for the unified PCM application.
 * Applies transaction management to use cases without using @Transactional annotations.
 * This keeps use cases framework-agnostic while ensuring transactional behavior.
 */
@Configuration
public class TransactionConfiguration {

    /**
     * Configure transaction interceptor with rollback rules.
     * Named 'pcmTransactionInterceptor' to avoid conflict with Spring's default transactionInterceptor.
     */
    @Bean("pcmTransactionInterceptor")
    public TransactionInterceptor transactionInterceptor(PlatformTransactionManager transactionManager) {
        TransactionInterceptor interceptor = new TransactionInterceptor();
        interceptor.setTransactionManager(transactionManager);
        
        Properties transactionAttributes = new Properties();
        // Apply PROPAGATION_REQUIRED with rollback on all exceptions
        transactionAttributes.setProperty("execute*", "PROPAGATION_REQUIRED,-Exception");
        transactionAttributes.setProperty("save*", "PROPAGATION_REQUIRED,-Exception");
        transactionAttributes.setProperty("delete*", "PROPAGATION_REQUIRED,-Exception");
        transactionAttributes.setProperty("update*", "PROPAGATION_REQUIRED,-Exception");
        transactionAttributes.setProperty("create*", "PROPAGATION_REQUIRED,-Exception");
        transactionAttributes.setProperty("grant*", "PROPAGATION_REQUIRED,-Exception");
        transactionAttributes.setProperty("revoke*", "PROPAGATION_REQUIRED,-Exception");
        transactionAttributes.setProperty("erase*", "PROPAGATION_REQUIRED,-Exception");
        
        // Read-only for query methods
        transactionAttributes.setProperty("get*", "PROPAGATION_REQUIRED,readOnly");
        transactionAttributes.setProperty("find*", "PROPAGATION_REQUIRED,readOnly");
        transactionAttributes.setProperty("verify*", "PROPAGATION_REQUIRED,readOnly");
        
        interceptor.setTransactionAttributes(transactionAttributes);
        return interceptor;
    }

    /**
     * Auto-proxy creator to apply transaction interceptor to use case beans.
     */
    @Bean
    public BeanNameAutoProxyCreator transactionAutoProxy() {
        BeanNameAutoProxyCreator creator = new BeanNameAutoProxyCreator();
        creator.setProxyTargetClass(true);
        
        // Apply to all use case beans
        creator.setBeanNames(
            "*UseCase",
            "createPreferenceUseCase",
            "updatePreferenceUseCase",
            "getPreferenceUseCase",
            "deletePreferenceUseCase",
            "createProfileUseCase",
            "updateProfileUseCase",
            "getProfileUseCase",
            "eraseProfileUseCase",
            "grantConsentUseCase",
            "revokeConsentUseCase",
            "verifyConsentUseCase",
            "getConsentHistoryUseCase",
            "createSegmentUseCase",
            "updateSegmentUseCase",
            "getSegmentUseCase",
            "evaluateSegmentForPreferenceUseCase",
            "evaluateSegmentForProfileUseCase",
            "revokeConsentsForProfileUseCase"
        );
        
        creator.setInterceptorNames("pcmTransactionInterceptor");
        return creator;
    }
}
