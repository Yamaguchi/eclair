package fr.acinq.eclair.api

import grizzled.slf4j.Logging
import io.grpc.{Server, ServerBuilder}

class GrpcServer(server: Server, port: Int) extends Logging {

  def start() = {
    server.start()
    logger.info(s"Starting grpc server at port=$port")
  }
}

object GrpcServer {

  def apply(port: Int): GrpcServer = {
    val server = ServerBuilder.forPort(port)
      .addService(new GreeterService)
      .build()

    new GrpcServer(server, port)
  }
}
