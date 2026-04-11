package dev.vibeafrika.pcm.domain.encryption;

import java.util.List;
import java.util.UUID;

/**
 * Domain interface for handling key compromise incidents.
 *
 * <p>The KeyCompromiseHandler is responsible for:
 * <ul>
 *   <li>Immediately revoking a compromised key</li>
 *   <li>Identifying all data encrypted with the compromised key</li>
 *   <li>Re-encrypting affected data with a new key</li>
 *   <li>Generating an incident report with affected data scope</li>
 * </ul>
 *
 * <p>Security guarantees:
 * <ul>
 *   <li>Key revocation is immediate and invalidates the cache</li>
 *   <li>Incident reports NEVER contain plaintext PII or key material</li>
 *   <li>All incident response actions are audit-logged</li>
 * </ul>
 */
public interface IKeyCompromiseHandler {

    /**
     * Immediately revokes a compromised key by marking it as COMPROMISED and
     * invalidating it from the DEK cache.
     *
     * <p>This is the first step in incident response and must be called as soon
     * as a compromise is detected.
     *
     * @param keyId the UUID of the compromised DEK
     * @return Result containing Unit on success, or IncidentError on failure
     */
    Result<Unit, IncidentError> revokeKey(UUID keyId);

    /**
     * Identifies all data encrypted with the given key ID.
     *
     * <p>Returns a list of field identifiers / record IDs that were encrypted
     * with the compromised key. This information is used to scope the incident
     * and drive re-encryption.
     *
     * @param keyId the UUID of the compromised DEK
     * @return Result containing a list of affected field/record identifiers, or IncidentError on failure
     */
    Result<List<String>, IncidentError> identifyAffectedData(UUID keyId);

    /**
     * Re-encrypts all data in the given bounded context that was encrypted with
     * the compromised key, using a freshly rotated DEK.
     *
     * <p>This method:
     * <ol>
     *   <li>Rotates the DEK for the context to obtain a new key</li>
     *   <li>Re-encrypts all identified affected records with the new key</li>
     *   <li>Logs the re-encryption event</li>
     * </ol>
     *
     * <p>Returns the count of records successfully re-encrypted.
     *
     * @param compromisedKeyId the UUID of the compromised DEK
     * @param context          the bounded context containing the affected data
     * @return Result containing the count of re-encrypted records, or IncidentError on failure
     */
    Result<Integer, IncidentError> reEncryptWithNewKey(UUID compromisedKeyId, BoundedContext context);

    /**
     * Generates a comprehensive incident report for the key compromise event.
     *
     * <p>The report includes:
     * <ul>
     *   <li>Incident ID and timestamp</li>
     *   <li>Compromised key information</li>
     *   <li>Affected data scope (field identifiers, not plaintext values)</li>
     *   <li>Actions taken during incident response</li>
     *   <li>New key ID used for re-encryption (if applicable)</li>
     * </ul>
     *
     * <p>The report MUST NOT contain plaintext PII or key material.
     *
     * @param keyId               the UUID of the compromised DEK
     * @param incidentDescription a human-readable description of how the compromise was detected
     * @return Result containing an IncidentReport on success, or IncidentError on failure
     */
    Result<IncidentReport, IncidentError> generateIncidentReport(UUID keyId, String incidentDescription);
}
