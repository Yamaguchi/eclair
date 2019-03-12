package fr.acinq.eclair.api

import akka.util.Timeout
import akka.pattern._
import akka.http.scaladsl.server._
import de.heikoseeberger.akkahttpjson4s.Json4sSupport.{ShouldWritePretty, marshaller, unmarshaller}
import fr.acinq.bitcoin.Crypto.PublicKey
import fr.acinq.bitcoin.{BinaryData, MilliSatoshi, Satoshi}
import fr.acinq.eclair.{Kit, ShortChannelId}
import fr.acinq.eclair.io.{NodeURI, Peer}
import org.json4s.jackson
import Marshallers._
import com.github.swagger.akka.SwaggerHttpService
import com.github.swagger.akka.model.Info
import de.heikoseeberger.akkahttpjson4s.Json4sSupport
import fr.acinq.eclair.channel.{CMD_CLOSE, Register}
import io.swagger.v3.oas.annotations.media.{Content, Schema}

import scala.concurrent.{ExecutionContext, Future}
import scala.concurrent.duration._
import io.swagger.v3.oas.annotations.responses.ApiResponse
import io.swagger.v3.oas.annotations.{Operation, Parameter}
import javax.ws.rs.{GET, Path}

trait NewService extends SwaggerHttpService {

  override val apiClasses: Set[Class[_]] = Set(ConnectRoute.getClass, GetInfoRoute.getClass)

  override val host = "127.0.0.1:9091"

  override val info = Info(description = "Eclair a lightning network implementation")

  override val apiDocsPath = "docs"

  def appKit: Kit

  def getInfoResponse: Future[GetInfoResponse]

  implicit val ec = appKit.system.dispatcher

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

  implicit val timeout = Timeout(60 seconds)
  implicit val shouldWritePretty: ShouldWritePretty = ShouldWritePretty.True
  import Json4sSupport.{marshaller, unmarshaller}

//  val connectRoute: Route = path("connect") {
//    parameters("nodeId".as[PublicKey], "address".as[NodeAddress]) { (nodeId, addr) =>
//      connect(s"$nodeId@$addr")
//    } ~ parameters("uri") { uri =>
//      connect(uri)
//    }
//  }
//
//  val openRoute: Route = path("open") {
//    parameters("nodeId".as[PublicKey], "fundingSatoshis".as[Long], "pushMsat".as[Long].?, "fundingFeerateSatByte".as[Long].?, "channelFlags".as[Int].?) {
//      (nodeId, fundingSatoshis, pushMsat, fundingFeerateSatByte, channelFlags) =>
//        open(nodeId, fundingSatoshis, pushMsat, fundingFeerateSatByte, channelFlags)
//    }
//  }
//
//  val closeRoute: Route = path("close") {
//    parameters("channelId".as[BinaryData](sha256HashUnmarshaller), "scriptPubKey".as[BinaryData](binaryDataUnmarshaller).?) { (channelId: BinaryData, scriptPubKey_opt: Option[BinaryData]) =>
//      close(channelId.toString(), scriptPubKey_opt)
//    }
//  }
//
//  val getInfoRoute: Route = path("getinfo") {
//    complete(getInfoResponse)
//  }

  @Path("getinfo")
  object GetInfoRoute extends ApiEndpoint {
    @GET @Operation(
      summary = "get info about this node",
      responses = Array(
        new ApiResponse(responseCode = "200", description = "Various information about this node", content = Array(new Content(schema = new Schema(implementation = classOf[GetInfoResponse])))),
        new ApiResponse(responseCode = "500", description = "Internal error"))
    )
    override def route: Route = path("getinfo"){
      get {
        complete(getInfoResponse)
      }
    }
  }

  @Path("connect")
  object ConnectRoute extends ApiEndpoint {
    @GET @Operation(
      summary = "connect to a node",
      responses = Array(
        new ApiResponse(responseCode = "200", description = "Ok if the connection was successful"),
        new ApiResponse(responseCode = "500", description = "Node unreachable"))
    )
    override def route: Route = path("connect") {
      get {
        complete("Yeah")
      }
    }
  }

//  val motherRoute: Route = {
//    get {
//      ConnectRoute.route ~
//      connectRoute ~
//      openRoute ~
//      closeRoute ~
//      getInfoRoute
//    }
//  }

  def connect(uri: String) : Route = {
    complete((appKit.switchboard ? Peer.Connect(NodeURI.parse(uri))).mapTo[String])
  }

  def open(nodeId: PublicKey, fundingSatoshis: Long, pushMsat: Option[Long], fundingFeerateSatByte: Option[Long], flags: Option[Int]): Route = {
    complete((appKit.switchboard ? Peer.OpenChannel(
      remoteNodeId = nodeId,
      fundingSatoshis = Satoshi(fundingSatoshis),
      pushMsat = pushMsat.map(MilliSatoshi).getOrElse(MilliSatoshi(0)),
      fundingTxFeeratePerKw_opt = fundingFeerateSatByte,
      channelFlags = flags.map(_.toByte))).mapTo[String])
  }

  def close(channelId: String, scriptPubKey: Option[BinaryData]) = {
    complete(sendToChannel(channelId, CMD_CLOSE(scriptPubKey)).mapTo[String])
  }

  /**
    * Sends a request to a channel and expects a response
    *
    * @param channelIdentifier can be a shortChannelId (BOLT encoded) or a channelId (32-byte hex encoded)
    * @param request
    * @return
    */
  def sendToChannel(channelIdentifier: String, request: Any): Future[Any] =
    for {
      fwdReq <- Future(Register.ForwardShortId(ShortChannelId(channelIdentifier), request))
        .recoverWith { case _ => Future(Register.Forward(BinaryData(channelIdentifier), request)) }
        .recoverWith { case _ => Future.failed(new RuntimeException(s"invalid channel identifier '$channelIdentifier'")) }
      res <- appKit.register ? fwdReq
    } yield res

}