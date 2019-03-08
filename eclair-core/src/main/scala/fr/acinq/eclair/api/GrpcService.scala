package fr.acinq.eclair.api

import fr.acinq.eclair.EclarService

class GrpcService {

  val getInfoResponse = EclarService.GetInfoResponse.newBuilder()
    .setAlias("alias")
    .setNodeId("NODE_ID")
    .setChainHash("asdasd")
    .setBlockHeight(2124)
    .setPort(9735)
    .build()



}
