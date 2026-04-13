/*
 * Copyright (c) 2023 European Commission
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

import android.content.Context
import android.util.Log
import eu.europa.ec.businesslogic.controller.storage.PrefsController
import eu.europa.ec.corelogic.BuildConfig
import eu.europa.ec.corelogic.model.DocumentIdentifier
import eu.europa.ec.eudi.wallet.EudiWalletConfig
import eu.europa.ec.eudi.wallet.document.CreateDocumentSettings.CredentialPolicy
import eu.europa.ec.eudi.wallet.issue.openid4vci.OpenId4VciManager
import eu.europa.ec.eudi.wallet.issue.openid4vci.dpop.DPopConfig
import eu.europa.ec.eudi.wallet.transfer.openId4vp.ClientIdScheme
import eu.europa.ec.eudi.wallet.transfer.openId4vp.Format
import eu.europa.ec.networklogic.repository.WalletAttestationRepository
import eu.europa.ec.resourceslogic.R
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONArray
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.time.Duration.Companion.seconds

internal class WalletCoreConfigImpl(
    private val context: Context,
    private val walletAttestationRepository: WalletAttestationRepository,
    private val prefsController: PrefsController
) : WalletCoreConfig {

    private companion object {
        private const val TAG = "WalletCoreConfig"
        private const val READER_CERTIFICATES_URL = "http://testsuite.hovi.id/certificate"
        private const val READER_CERTIFICATES_TIMEOUT_MS = 3_000L
        private const val READER_CERTIFICATES_CACHE_KEY = "reader_certificates_cache"
    }

    private var _config: EudiWalletConfig? = null

    override val config: EudiWalletConfig
        get() {
            if (_config == null) {
                _config = EudiWalletConfig {
                    configureDocumentKeyCreation(
                        userAuthenticationRequired = false,
                        userAuthenticationTimeout = 30.seconds,
                        useStrongBoxForKeys = true
                    )
                    configureOpenId4Vp {
                        withClientIdSchemes(
                            listOf(
                                ClientIdScheme.X509SanDns,
                                ClientIdScheme.X509Hash
                            )
                        )
                        withSchemes(
                            listOf(
                                BuildConfig.OPENID4VP_SCHEME,
                                BuildConfig.EUDI_OPENID4VP_SCHEME,
                                BuildConfig.MDOC_OPENID4VP_SCHEME,
                                BuildConfig.HAIP_OPENID4VP_SCHEME
                            )
                        )
                        withFormats(
                            Format.MsoMdoc.ES256, Format.SdJwtVc.ES256
                        )
                    }

                    configureReaderTrustStore(
                        *loadTrustedReaderCertificates().toTypedArray()
                    )
                }
            }
            return _config!!
        }

    override val issuersConfig: List<VciConfig>
        get() = listOf(
            VciConfig(
                config = OpenId4VciManager.Config.Builder()
                    .withIssuerUrl(issuerUrl = "https://ec.dev.issuer.eudiw.dev")
                    .withClientAuthenticationType(OpenId4VciManager.ClientAuthenticationType.AttestationBased)
                    .withAuthFlowRedirectionURI(BuildConfig.ISSUE_AUTHORIZATION_DEEPLINK)
                    .withParUsage(OpenId4VciManager.Config.ParUsage.IF_SUPPORTED)
                    .withDPopConfig(DPopConfig.Default)
                    .build(),
                order = 0
            ),
            VciConfig(
                config = OpenId4VciManager.Config.Builder()
                    .withIssuerUrl(issuerUrl = "https://dev.issuer-backend.eudiw.dev")
                    .withClientAuthenticationType(OpenId4VciManager.ClientAuthenticationType.AttestationBased)
                    .withAuthFlowRedirectionURI(BuildConfig.ISSUE_AUTHORIZATION_DEEPLINK)
                    .withParUsage(OpenId4VciManager.Config.ParUsage.IF_SUPPORTED)
                    .withDPopConfig(DPopConfig.Default)
                    .build(),
                order = 1
            ),
            VciConfig(
                config = OpenId4VciManager.Config.Builder()
                    .withIssuerUrl(issuerUrl = "https://test.id.cloud.dvv.fi/pid-issuer")
                    .withClientAuthenticationType(
                        OpenId4VciManager.ClientAuthenticationType.AttestationBased
                    )
                    .withAuthFlowRedirectionURI(BuildConfig.ISSUE_AUTHORIZATION_DEEPLINK)
                    .withParUsage(OpenId4VciManager.Config.ParUsage.IF_SUPPORTED)
                    .withDPopConfig(DPopConfig.Default)
                    .build(),
                order = 2
            ),
            VciConfig(
                config = OpenId4VciManager.Config.Builder()
                    .withIssuerUrl(issuerUrl = "https://core-agent.hovi.id")
                    .withClientAuthenticationType(
                        OpenId4VciManager.ClientAuthenticationType.None(
                            clientId = "wallet-client"
                        )
                    )
                    .withAuthFlowRedirectionURI(BuildConfig.ISSUE_AUTHORIZATION_DEEPLINK)
                    .withParUsage(OpenId4VciManager.Config.ParUsage.IF_SUPPORTED)
                    .withDPopConfig(DPopConfig.Default)
                    .build(),
                order = 3
            ),
            VciConfig(
                config = OpenId4VciManager.Config.Builder()
                    .withIssuerUrl(issuerUrl = "https://test-core-agent.hovi.id")
                    .withClientAuthenticationType(
                        OpenId4VciManager.ClientAuthenticationType.None(
                            clientId = "wallet-client"
                        )
                    )
                    .withAuthFlowRedirectionURI(BuildConfig.ISSUE_AUTHORIZATION_DEEPLINK)
                    .withParUsage(OpenId4VciManager.Config.ParUsage.IF_SUPPORTED)
                    .withDPopConfig(DPopConfig.Default)
                    .build(),
                order = 4
            )
        )

    override val documentIssuanceConfig: DocumentIssuanceConfig
        get() = DocumentIssuanceConfig(
            defaultRule = DocumentIssuanceRule(
                policy = CredentialPolicy.RotateUse,
                numberOfCredentials = 1
            ),
            documentSpecificRules = mapOf(
                DocumentIdentifier.MdocPid to DocumentIssuanceRule(
                    policy = CredentialPolicy.OneTimeUse,
                    numberOfCredentials = 60
                ),
                DocumentIdentifier.SdJwtPid to DocumentIssuanceRule(
                    policy = CredentialPolicy.OneTimeUse,
                    numberOfCredentials = 60
                ),
            )
        )

    override val walletProviderHost: String
        get() = "https://dev.wallet-provider.eudiw.dev"

    private fun loadTrustedReaderCertificates(): List<X509Certificate> {
        val rawEntries = listOf(
            R.raw.pidissuerca02_cz,
            R.raw.pidissuerca02_ee,
            R.raw.pidissuerca02_eu,
            R.raw.pidissuerca02_lu,
            R.raw.pidissuerca02_nl,
            R.raw.pidissuerca02_pt,
            R.raw.pidissuerca02_ut,
            R.raw.dc4eu,
            R.raw.r45_staging,
            R.raw.playground_hovi
        ).mapNotNull { resId ->
            parseRawCertificate(resId)?.let { cert ->
                "raw:${context.resources.getResourceEntryName(resId)}" to cert
            }
        }

        val fetchedCertificates = runBlocking {
            withTimeoutOrNull(READER_CERTIFICATES_TIMEOUT_MS) {
                walletAttestationRepository.getReaderCertificates(READER_CERTIFICATES_URL)
                    .onFailure {
                        Log.w(TAG, "Failed to fetch reader certificates", it)
                    }
                    .getOrNull()
            }
        }

        val remotePemCertificates = if (fetchedCertificates != null) {
            logReaderCertificates(source = "network", pemStrings = fetchedCertificates)
            cacheReaderCertificates(fetchedCertificates)
            fetchedCertificates
        } else {
            loadCachedReaderCertificates().also { cached ->
                logReaderCertificates(source = "cache-fallback", pemStrings = cached)
            }
        }

        val remoteEntries = remotePemCertificates.mapIndexedNotNull { index, pem ->
            parsePemCertificate(pem)?.let { cert -> "fetched-pem[$index]" to cert }
        }

        return mergeAndLogReaderTrustCertificates(
            tag = TAG,
            rawEntries = rawEntries,
            remoteEntries = remoteEntries
        )
    }

    private fun parseRawCertificate(rawResId: Int): X509Certificate? = runCatching {
        context.resources.openRawResource(rawResId).use { input ->
            CertificateFactory.getInstance("X.509")
                .generateCertificate(input) as X509Certificate
        }
    }.getOrElse {
        Log.w(TAG, "Invalid hardcoded certificate resource=$rawResId", it)
        null
    }

    private fun parsePemCertificate(pemCertificate: String): X509Certificate? = runCatching {
        CertificateFactory.getInstance("X.509")
            .generateCertificate(
                ByteArrayInputStream(pemCertificate.toByteArray(Charsets.UTF_8))
            ) as X509Certificate
    }.getOrElse {
        Log.w(TAG, "Invalid remote certificate payload", it)
        null
    }

    private fun cacheReaderCertificates(certificates: List<String>) {
        runCatching {
            prefsController.setString(
                key = READER_CERTIFICATES_CACHE_KEY,
                value = JSONArray(certificates).toString()
            )
            Log.d(TAG, "Reader certificates saved to prefs: count=${certificates.size}")
        }.onFailure {
            Log.w(TAG, "Failed to cache reader certificates", it)
        }
    }

    private fun logReaderCertificates(source: String, pemStrings: List<String>) {
        Log.d(TAG, "Reader certificates ($source): count=${pemStrings.size}")
        pemStrings.forEachIndexed { index, pem ->
            Log.d(TAG, "[$source][$index] --- PEM start ---")
            pem.chunked(3500).forEach { chunk -> Log.d(TAG, chunk) }
            Log.d(TAG, "[$source][$index] --- PEM end ---")
            runCatching {
                CertificateFactory.getInstance("X.509")
                    .generateCertificate(
                        ByteArrayInputStream(pem.toByteArray(Charsets.UTF_8))
                    ) as X509Certificate
            }.onSuccess { cert ->
                Log.d(
                    TAG,
                    "[$source][$index] subject=${cert.subjectX500Principal.name} " +
                        "issuer=${cert.issuerX500Principal.name}"
                )
            }.onFailure {
                Log.w(TAG, "[$source][$index] PEM logged but not parseable as X.509", it)
            }
        }
    }

    private fun loadCachedReaderCertificates(): List<String> = runCatching {
        val cachedValue = prefsController.getString(READER_CERTIFICATES_CACHE_KEY, "")
        if (cachedValue.isBlank()) {
            emptyList()
        } else {
            val jsonArray = JSONArray(cachedValue)
            buildList {
                for (index in 0 until jsonArray.length()) {
                    val certificate = jsonArray.optString(index).trim()
                    if (certificate.isNotBlank()) add(certificate)
                }
            }
        }
    }.onFailure {
        Log.w(TAG, "Failed to load cached reader certificates", it)
    }.getOrDefault(emptyList())
}