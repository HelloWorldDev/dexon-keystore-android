package org.dexon.dekusan.keystore

import org.dexon.dekusan.core.model.Address
import org.kethereum.crypto.model.ECKeyPair

data class Credentials(val ecKeyPair: ECKeyPair?, val address: Address)