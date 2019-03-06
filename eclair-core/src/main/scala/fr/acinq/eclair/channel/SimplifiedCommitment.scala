package fr.acinq.eclair.channel

import akka.event.LoggingAdapter
import fr.acinq.bitcoin._
import fr.acinq.bitcoin.{BinaryData, Satoshi, Transaction}
import fr.acinq.bitcoin.Crypto.{Point, PublicKey}
import fr.acinq.eclair.crypto.{Generators, KeyManager, ShaChain}
import fr.acinq.eclair.payment.Origin
import fr.acinq.eclair.transactions.{CommitmentSpec, Transactions}
import fr.acinq.eclair.transactions.Transactions._
import fr.acinq.eclair.wire.{CommitSig, RevokeAndAck, UpdateFee, UpdateMessage}

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

  override def receiveCommit(commit: CommitSig, keyManager: KeyManager)(implicit log: LoggingAdapter): (Commitments, RevokeAndAck) =
    super.receiveCommit(commit, keyManager, htlcSigHashFlag = SIGHASH_SINGLE | SIGHASH_ANYONECANPAY)

  override def makeLocalTxs(keyManager: KeyManager, commitTxNumber: Long, localParams: LocalParams, remoteParams: RemoteParams, commitmentInput: InputInfo, localPerCommitmentPoint: Point, remotePerCommitmentPoint: Point, spec: CommitmentSpec): (CommitTx, Seq[HtlcTimeoutTx], Seq[HtlcSuccessTx]) = {
    SimplifiedCommitment.makeLocalTxs(keyManager, commitTxNumber, localParams, remoteParams, commitmentInput, localPerCommitmentPoint, remotePerCommitmentPoint, spec)
  }

}

object SimplifiedCommitment {

  def makeLocalTxs(keyManager: KeyManager, commitTxNumber: Long, localParams: LocalParams, remoteParams: RemoteParams, commitmentInput: InputInfo, localPerCommitmentPoint: Point, remotePerCommitmentPoint: Point, spec: CommitmentSpec): (CommitTx, Seq[HtlcTimeoutTx], Seq[HtlcSuccessTx]) = {
    val localDelayedPaymentPubkey = Generators.derivePubKey(keyManager.delayedPaymentPoint(localParams.channelKeyPath).publicKey, localPerCommitmentPoint)
    val localHtlcPubkey = Generators.derivePubKey(keyManager.htlcPoint(localParams.channelKeyPath).publicKey, localPerCommitmentPoint)
    val remotePaymentPubkey = PublicKey(remoteParams.paymentBasepoint)
    val remoteDelayedPaymentPubkey = Generators.derivePubKey(remoteParams.delayedPaymentBasepoint, remotePerCommitmentPoint)
    val remoteHtlcPubkey = Generators.derivePubKey(remoteParams.htlcBasepoint, localPerCommitmentPoint)
    val localRevocationPubkey = Generators.revocationPubKey(remoteParams.revocationBasepoint, localPerCommitmentPoint)
    val commitTx = Transactions.makeSimplifiedCommitTx(commitmentInput, commitTxNumber, keyManager.paymentPoint(localParams.channelKeyPath).publicKey, remoteParams.paymentBasepoint, localParams.isFunder, Satoshi(localParams.dustLimitSatoshis), localRevocationPubkey, remoteParams.toSelfDelay, localDelayedPaymentPubkey, remotePaymentPubkey, localHtlcPubkey, remoteHtlcPubkey, remoteDelayedPaymentPubkey, spec)
    val (htlcTimeoutTxs, htlcSuccessTxs) = Transactions.makeHtlcTxs(commitTx.tx, Satoshi(localParams.dustLimitSatoshis), localRevocationPubkey, remoteParams.toSelfDelay, localDelayedPaymentPubkey, localHtlcPubkey, remoteHtlcPubkey, spec)(ContextSimplifiedCommitment)
    (commitTx, htlcTimeoutTxs, htlcSuccessTxs)
  }

}