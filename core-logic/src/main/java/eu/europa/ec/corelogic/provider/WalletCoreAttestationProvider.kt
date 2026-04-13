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

package eu.europa.ec.corelogic.provider

import android.util.Log
import eu.europa.ec.corelogic.config.WalletCoreConfig
import eu.europa.ec.eudi.openid4vci.Nonce
import eu.europa.ec.eudi.wallet.provider.WalletAttestationsProvider
import eu.europa.ec.networklogic.repository.WalletAttestationRepository
import org.multipaz.securearea.KeyInfo

interface WalletCoreAttestationProvider : WalletAttestationsProvider

class WalletCoreAttestationProviderImpl(
    private val walletCoreConfig: WalletCoreConfig,
    private val walletAttestationRepository: WalletAttestationRepository
) : WalletCoreAttestationProvider {

    private companion object {
        private const val TAG = "OID4VCI_ATTESTATION"
    }

    override suspend fun getWalletAttestation(
        keyInfo: KeyInfo
    ): Result<String> {
        val baseUrl = walletCoreConfig.walletProviderHost
        Log.d(TAG, "getWalletAttestation: baseUrl=$baseUrl")
        return walletAttestationRepository.getWalletAttestation(
            baseUrl = baseUrl,
            keyInfo = keyInfo.publicKey.toJwk()
        )
            .onSuccess { jwt ->
                Log.d(TAG, "getWalletAttestation: OK jwtLength=${jwt.length}")
            }
            .onFailure { e ->
                Log.e(TAG, "getWalletAttestation: FAILED", e)
            }
    }

    override suspend fun getKeyAttestation(
        keys: List<KeyInfo>,
        nonce: Nonce?
    ): Result<String> {
        val baseUrl = walletCoreConfig.walletProviderHost
        Log.d(TAG, "getKeyAttestation: baseUrl=$baseUrl keysCount=${keys.size} nonce=${nonce != null}")
        return walletAttestationRepository.getKeyAttestation(
            baseUrl = baseUrl,
            keys = keys.map { it.publicKey.toJwk() },
            nonce = nonce?.value
        )
            .onSuccess { jwt ->
                Log.d(TAG, "getKeyAttestation: OK jwtLength=${jwt.length}")
            }
            .onFailure { e ->
                Log.e(TAG, "getKeyAttestation: FAILED", e)
            }
    }
}