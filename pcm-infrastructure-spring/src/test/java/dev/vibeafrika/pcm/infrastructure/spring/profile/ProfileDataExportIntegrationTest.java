package dev.vibeafrika.pcm.infrastructure.spring.profile;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.vibeafrika.pcm.profile.application.dto.ProfileDataExportResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for Profile Data Export functionality.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class ProfileDataExportIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private static final String TENANT_ID = "test-tenant";
    private UUID profileId;

    @BeforeEach
    void setUp() throws Exception {
        // Create a test profile
        String createProfileRequest = """
            {
                "handle": "exporttest",
                "attributes": {
                    "fullName": "Export Test User",
                    "email": "export@test.com",
                    "country": "CI"
                }
            }
            """;

        MvcResult createResult = mockMvc.perform(post("/api/v1/profiles")
                        .header("X-Tenant-Id", TENANT_ID)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createProfileRequest))
                .andExpect(status().isCreated())
                .andReturn();

        String responseBody = createResult.getResponse().getContentAsString();
        Map<String, Object> profileResponse = objectMapper.readValue(responseBody, Map.class);
        profileId = UUID.fromString((String) profileResponse.get("id"));

        // Grant some consents
        String grantConsentRequest = String.format("""
            {
                "profileId": "%s",
                "tenantId": "%s",
                "purpose": "MARKETING",
                "scope": "EMAIL"
            }
            """, profileId, TENANT_ID);

        mockMvc.perform(post("/api/v1/consents")
                        .header("X-Tenant-Id", TENANT_ID)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(grantConsentRequest))
                .andExpect(status().isCreated());

        // Create some preferences
        String createPreferenceRequest = String.format("""
            {
                "profileId": "%s",
                "tenantId": "%s",
                "key": "ui.theme",
                "value": "dark"
            }
            """, profileId, TENANT_ID);

        mockMvc.perform(post("/api/v1/preferences")
                        .header("X-Tenant-Id", TENANT_ID)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createPreferenceRequest))
                .andExpect(status().isCreated());
    }

    @Test
    @DisplayName("Should export all profile data in structured JSON format")
    void shouldExportAllProfileData() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/v1/profiles/{id}/export", profileId)
                        .header("X-Tenant-Id", TENANT_ID))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andReturn();

        String responseBody = result.getResponse().getContentAsString();
        ProfileDataExportResponse exportResponse = objectMapper.readValue(responseBody, ProfileDataExportResponse.class);

        // Verify profile section
        assertThat(exportResponse.profileId()).isEqualTo(profileId);
        assertThat(exportResponse.tenantId()).isEqualTo(TENANT_ID);
        assertThat(exportResponse.exportedAt()).isNotNull();
        
        assertThat(exportResponse.profile()).isNotNull();
        assertThat(exportResponse.profile().handle()).isEqualTo("exporttest");
        assertThat(exportResponse.profile().attributes())
                .containsEntry("fullName", "Export Test User")
                .containsEntry("email", "export@test.com")
                .containsEntry("country", "CI");

        // Verify consents section
        assertThat(exportResponse.consents()).isNotEmpty();
        assertThat(exportResponse.consents().get(0).purpose()).isEqualTo("MARKETING");
        assertThat(exportResponse.consents().get(0).scope()).isEqualTo("EMAIL");
        assertThat(exportResponse.consents().get(0).currentStatus()).isEqualTo("GRANTED");
        assertThat(exportResponse.consents().get(0).history()).isNotEmpty();

        // Verify preferences section
        assertThat(exportResponse.preferences()).isNotEmpty();
        assertThat(exportResponse.preferences().get(0).settings())
                .containsEntry("ui.theme", "dark");
    }

    @Test
    @DisplayName("Should return 404 for non-existent profile")
    void shouldReturn404ForNonExistentProfile() throws Exception {
        UUID nonExistentId = UUID.randomUUID();

        mockMvc.perform(get("/api/v1/profiles/{id}/export", nonExistentId)
                        .header("X-Tenant-Id", TENANT_ID))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("Should enforce tenant isolation in export")
    void shouldEnforceTenantIsolationInExport() throws Exception {
        // Try to export with different tenant ID
        mockMvc.perform(get("/api/v1/profiles/{id}/export", profileId)
                        .header("X-Tenant-Id", "different-tenant"))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("Should export empty consents and preferences if none exist")
    void shouldExportEmptyCollectionsIfNoData() throws Exception {
        // Create a profile without consents or preferences
        String createProfileRequest = """
            {
                "handle": "emptyexport",
                "attributes": {
                    "fullName": "Empty Export User"
                }
            }
            """;

        MvcResult createResult = mockMvc.perform(post("/api/v1/profiles")
                        .header("X-Tenant-Id", TENANT_ID)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createProfileRequest))
                .andExpect(status().isCreated())
                .andReturn();

        String responseBody = createResult.getResponse().getContentAsString();
        Map<String, Object> profileResponse = objectMapper.readValue(responseBody, Map.class);
        UUID emptyProfileId = UUID.fromString((String) profileResponse.get("id"));

        MvcResult exportResult = mockMvc.perform(get("/api/v1/profiles/{id}/export", emptyProfileId)
                        .header("X-Tenant-Id", TENANT_ID))
                .andExpect(status().isOk())
                .andReturn();

        String exportBody = exportResult.getResponse().getContentAsString();
        ProfileDataExportResponse exportResponse = objectMapper.readValue(exportBody, ProfileDataExportResponse.class);

        assertThat(exportResponse.profile()).isNotNull();
        assertThat(exportResponse.consents()).isEmpty();
        assertThat(exportResponse.preferences()).isEmpty();
    }

    @Test
    @DisplayName("Should include consent event history in export")
    void shouldIncludeConsentEventHistory() throws Exception {
        // Grant a consent
        String grantConsentRequest = String.format("""
            {
                "profileId": "%s",
                "tenantId": "%s",
                "purpose": "ANALYTICS",
                "scope": "TRACKING"
            }
            """, profileId, TENANT_ID);

        MvcResult grantResult = mockMvc.perform(post("/api/v1/consents")
                        .header("X-Tenant-Id", TENANT_ID)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(grantConsentRequest))
                .andExpect(status().isCreated())
                .andReturn();

        String grantBody = grantResult.getResponse().getContentAsString();
        Map<String, Object> consentResponse = objectMapper.readValue(grantBody, Map.class);
        String consentId = (String) consentResponse.get("id");

        // Revoke the consent
        mockMvc.perform(delete("/api/v1/consents/{id}", consentId)
                        .header("X-Tenant-Id", TENANT_ID))
                .andExpect(status().isOk());

        // Export and verify event history
        MvcResult exportResult = mockMvc.perform(get("/api/v1/profiles/{id}/export", profileId)
                        .header("X-Tenant-Id", TENANT_ID))
                .andExpect(status().isOk())
                .andReturn();

        String exportBody = exportResult.getResponse().getContentAsString();
        ProfileDataExportResponse exportResponse = objectMapper.readValue(exportBody, ProfileDataExportResponse.class);

        // Find the ANALYTICS consent
        var analyticsConsent = exportResponse.consents().stream()
                .filter(c -> "ANALYTICS".equals(c.purpose()))
                .findFirst()
                .orElseThrow();

        // Verify it has both GRANTED and REVOKED events
        assertThat(analyticsConsent.history()).hasSizeGreaterThanOrEqualTo(2);
        assertThat(analyticsConsent.history().stream()
                .map(ProfileDataExportResponse.ConsentEventEntry::status))
                .contains("GRANTED", "REVOKED");
    }

    @Test
    @DisplayName("Should decrypt PII in export (user receives clear text)")
    void shouldDecryptPiiInExport() throws Exception {
        // Update profile with encrypted PII
        String updateRequest = """
            {
                "attributes": {
                    "email": "encrypted@test.com",
                    "phone": "+225-01-23-45-67"
                }
            }
            """;

        mockMvc.perform(put("/api/v1/profiles/{id}", profileId)
                        .header("X-Tenant-Id", TENANT_ID)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(updateRequest))
                .andExpect(status().isOk());

        // Export and verify PII is decrypted
        MvcResult exportResult = mockMvc.perform(get("/api/v1/profiles/{id}/export", profileId)
                        .header("X-Tenant-Id", TENANT_ID))
                .andExpect(status().isOk())
                .andReturn();

        String exportBody = exportResult.getResponse().getContentAsString();
        ProfileDataExportResponse exportResponse = objectMapper.readValue(exportBody, ProfileDataExportResponse.class);

        // Verify PII is in clear text (not encrypted)
        assertThat(exportResponse.profile().attributes())
                .containsEntry("email", "encrypted@test.com")
                .containsEntry("phone", "+225-01-23-45-67");
        
        // Verify values are not encrypted (no base64 or hex encoding)
        String email = (String) exportResponse.profile().attributes().get("email");
        assertThat(email).doesNotContainPattern("[A-Za-z0-9+/=]{20,}"); // Not base64
        assertThat(email).contains("@"); // Valid email format
    }

    @Test
    @DisplayName("Should return 410 Gone for erased profile")
    void shouldReturn410ForErasedProfile() throws Exception {
        // Erase the profile
        mockMvc.perform(delete("/api/v1/profiles/{id}", profileId)
                        .header("X-Tenant-Id", TENANT_ID))
                .andExpect(status().isNoContent());

        // Try to export erased profile
        mockMvc.perform(get("/api/v1/profiles/{id}/export", profileId)
                        .header("X-Tenant-Id", TENANT_ID))
                .andExpect(status().isGone());
    }
}
