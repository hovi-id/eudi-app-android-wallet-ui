/*
 * Copyright (c) 2025 European Commission
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European
 * Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work
 * except in compliance with the Licence.
 *
 * You may obtain a copy of the Licence at:
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the Licence for the specific language
 * governing permissions and limitations under the Licence.
 */

package eu.europa.ec.corelogic.config

import android.util.Log
import java.security.cert.X509Certificate

/**
 * Merges raw-resource and remotely fetched reader certificates, dedupes by encoded cert bytes,
 * and logs each entry for debugging issuance vs verification trust-store issues.
 */
internal fun mergeAndLogReaderTrustCertificates(
    tag: String,
    rawEntries: List<Pair<String, X509Certificate>>,
    remoteEntries: List<Pair<String, X509Certificate>>,
): List<X509Certificate> {
    val combined = rawEntries + remoteEntries
    val seenHashes = mutableSetOf<Int>()
    val merged = mutableListOf<Pair<String, X509Certificate>>()

    for ((source, cert) in combined) {
        val hash = cert.encoded.contentHashCode()
        if (hash in seenHashes) {
            Log.d(
                tag,
                "Reader trust store: skipped duplicate (same encoded bytes) source=$source " +
                    "serial=${cert.serialNumber.toString(16)} subject=${cert.subjectX500Principal.name}"
            )
            continue
        }
        seenHashes.add(hash)
        merged.add(source to cert)
    }

    Log.d(
        tag,
        "Reader trust store merge: rawCount=${rawEntries.size} remoteCount=${remoteEntries.size} " +
            "combinedBeforeDedupe=${combined.size} finalAfterDedupe=${merged.size}"
    )
    merged.forEachIndexed { index, (source, cert) ->
        Log.d(
            tag,
            "Reader trust store[$index] source=$source " +
                "serial=${cert.serialNumber.toString(16)} " +
                "subject=${cert.subjectX500Principal.name} " +
                "issuer=${cert.issuerX500Principal.name}"
        )
    }
    return merged.map { it.second }
}
