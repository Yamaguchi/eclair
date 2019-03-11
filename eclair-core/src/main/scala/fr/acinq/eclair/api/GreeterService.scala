package fr.acinq.eclair.api

import com.example.protos.Hello.HelloReply
import com.example.protos.{GreeterGrpc, Hello}
import grizzled.slf4j.Logging
import io.grpc.stub.StreamObserver

class GreeterService() extends GreeterGrpc.GreeterImplBase with Logging {

  override def sayHello(request: Hello.HelloRequest, responseObserver: StreamObserver[Hello.HelloReply]): Unit = {
    val name = request.getName()
    val helloResponse = HelloReply
      .newBuilder()
      .setMessage(s"Hello to $name!")
      .build()

    responseObserver.onNext(helloResponse)
    responseObserver.onCompleted()
  }


}

