package org.dexon.wallet.keystore

import org.dexon.wallet.core.model.Address
import org.kethereum.model.ECKeyPair

data class Credentials(val ecKeyPair: ECKeyPair?, val address: Address)