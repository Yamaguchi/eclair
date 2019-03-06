package fr.acinq.eclair.channel

import fr.acinq.bitcoin.BinaryData
import fr.acinq.bitcoin.Crypto.Point
import fr.acinq.eclair.crypto.ShaChain
import fr.acinq.eclair.payment.Origin
import fr.acinq.eclair.transactions.Transactions.InputInfo
import fr.acinq.eclair.wire.{UpdateFee, UpdateMessage}

case class SimplifiedCommitment(localParams: LocalParams, remoteParams: RemoteParams,
                                channelFlags: Byte,
                                localCommit: LocalCommit, remoteCommit: RemoteCommit,
                                localChanges: LocalChanges, remoteChanges: RemoteChanges,
                                localNextHtlcId: Long,
                                remoteNextHtlcId: Long,
                                originChannels: Map[Long, Origin], // for outgoing htlcs relayed through us, the id of the previous channel
                                remoteNextCommitInfo: Either[WaitingForRevocation, Point],
                                commitInput: InputInfo,
                                remotePerCommitmentSecrets: ShaChain,
                                channelId: BinaryData) extends Commitments {


  override def getContext: CommitmentContext = ContextSimplifiedCommitment

  override def addLocalProposal(proposal: UpdateMessage): Commitments = this.copy(localChanges = localChanges.copy(proposed = localChanges.proposed :+ proposal))

  override def addRemoteProposal(proposal: UpdateMessage): Commitments = this.copy(remoteChanges = remoteChanges.copy(proposed = remoteChanges.proposed :+ proposal))

  override def sendFee(cmd: CMD_UPDATE_FEE): (Commitments, UpdateFee) = throw CannotUpdateFeeWithCommitmentType(channelId)

  override def receiveFee(fee: UpdateFee, maxFeerateMismatch: Double): Commitments = throw CannotUpdateFeeWithCommitmentType(channelId)
}
