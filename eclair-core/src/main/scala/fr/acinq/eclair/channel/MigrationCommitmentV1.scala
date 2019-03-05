package fr.acinq.eclair.channel

import fr.acinq.bitcoin.BinaryData
import fr.acinq.bitcoin.Crypto.Point
import fr.acinq.eclair.crypto.ShaChain
import fr.acinq.eclair.payment.Origin
import fr.acinq.eclair.transactions.Transactions.InputInfo

//case class MigrationCommitmentV1(localParams: LocalParams, remoteParams: RemoteParams,
//                                 channelFlags: Byte,
//                                 localCommit: LocalCommit, remoteCommit: RemoteCommit,
//                                 localChanges: LocalChanges, remoteChanges: RemoteChanges,
//                                 localNextHtlcId: Long, remoteNextHtlcId: Long,
//                                 originChannels: Map[Long, Origin], // for outgoing htlcs relayed through us, the id of the previous channel
//                                 remoteNextCommitInfo: Either[WaitingForRevocation, Point],
//                                 commitInput: InputInfo,
//                                 remotePerCommitmentSecrets: ShaChain, channelId: BinaryData) extends Commitments {
//
//  override def getContext: CommitmentContext = ContextCommitmentV1
//
//
//
//
//
//}
//
//object MigrationCommitmentV1 {
//
//}
