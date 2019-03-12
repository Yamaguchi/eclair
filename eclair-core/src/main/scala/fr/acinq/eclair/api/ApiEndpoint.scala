package fr.acinq.eclair.api

import akka.http.scaladsl.server.{Directives, Route}
import akka.util.Timeout
import de.heikoseeberger.akkahttpjson4s.Json4sSupport
import de.heikoseeberger.akkahttpjson4s.Json4sSupport.{ShouldWritePretty, marshaller, unmarshaller}
import fr.acinq.eclair.Kit
import org.json4s.jackson

trait ApiEndpoint extends Directives {

  def route: Route

  implicit val serialization = jackson.Serialization
  implicit val formats = org.json4s.DefaultFormats +
    new BinaryDataSerializer +
    new UInt64Serializer +
    new MilliSatoshiSerializer +
    new ShortChannelIdSerializer +
    new StateSerializer +
    new ShaChainSerializer +
    new PublicKeySerializer +
    new PrivateKeySerializer +
    new ScalarSerializer +
    new PointSerializer +
    new TransactionSerializer +
    new TransactionWithInputInfoSerializer +
    new InetSocketAddressSerializer +
    new OutPointSerializer +
    new OutPointKeySerializer +
    new InputInfoSerializer +
    new ColorSerializer +
    new RouteResponseSerializer +
    new ThrowableSerializer +
    new FailureMessageSerializer +
    new NodeAddressSerializer +
    new DirectionSerializer +
    new PaymentRequestSerializer

  implicit val shouldWritePretty: ShouldWritePretty = ShouldWritePretty.True
  import Json4sSupport.{marshaller, unmarshaller}

}
