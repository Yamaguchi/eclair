/*
 * Copyright 2018 ACINQ SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.acinq.eclair.channel

import akka.event.LoggingAdapter
import fr.acinq.bitcoin.Crypto.{Point, PrivateKey, PublicKey, sha256}
import fr.acinq.bitcoin.{BinaryData, Crypto, MilliSatoshi, Satoshi, Transaction}
import fr.acinq.eclair.crypto.{Generators, KeyManager, ShaChain, Sphinx}
import fr.acinq.eclair.payment._
import fr.acinq.eclair.transactions.Transactions._
import fr.acinq.eclair.transactions._
import fr.acinq.eclair.wire._
import fr.acinq.eclair.{Features, Globals, UInt64}
import fr.acinq.bitcoin._
import fr.acinq.eclair.channel.Commitments.{makeLocalTxs, makeRemoteTxs, msg2String}

import scala.util.{Failure, Success}

// @formatter:off
case class LocalChanges(proposed: List[UpdateMessage], signed: List[UpdateMessage], acked: List[UpdateMessage]) {
  def all: List[UpdateMessage] = proposed ++ signed ++ acked
}
case class RemoteChanges(proposed: List[UpdateMessage], acked: List[UpdateMessage], signed: List[UpdateMessage])
case class Changes(ourChanges: LocalChanges, theirChanges: RemoteChanges)
case class HtlcTxAndSigs(txinfo: TransactionWithInputInfo, localSig: BinaryData, remoteSig: BinaryData)
case class PublishableTxs(commitTx: CommitTx, htlcTxsAndSigs: List[HtlcTxAndSigs])
case class LocalCommit(index: Long, spec: CommitmentSpec, publishableTxs: PublishableTxs)
case class RemoteCommit(index: Long, spec: CommitmentSpec, txid: BinaryData, remotePerCommitmentPoint: Point)
case class WaitingForRevocation(nextRemoteCommit: RemoteCommit, sent: CommitSig, sentAfterLocalCommitIndex: Long, reSignAsap: Boolean = false)
// @formatter:on

trait Commitments {

  val localParams: LocalParams
  val remoteParams: RemoteParams
  val channelFlags: Byte
  val localCommit: LocalCommit
  val remoteCommit: RemoteCommit
  val localChanges: LocalChanges
  val remoteChanges: RemoteChanges
  val localNextHtlcId: Long
  val remoteNextHtlcId: Long
  val originChannels: Map[Long, Origin] // for outgoing htlcs relayed through us, the id of the previous channel
  val remoteNextCommitInfo: Either[WaitingForRevocation, Point]
  val commitInput: InputInfo
  val remotePerCommitmentSecrets: ShaChain
  val channelId: BinaryData


  def hasNoPendingHtlcs: Boolean = localCommit.spec.htlcs.isEmpty && remoteCommit.spec.htlcs.isEmpty && remoteNextCommitInfo.isRight

  /**
    * add a change to our proposed change list
    *
    * @param proposal
    * @return an updated commitment instance
    */
  def addLocalProposal(proposal: UpdateMessage): Commitments

  /**
    * add a change to the remote proposed change list
    *
    * @param proposal
    * @return an updated commitment instance
    */
  def addRemoteProposal(proposal: UpdateMessage): Commitments

  def timedoutOutgoingHtlcs(blockheight: Long): Set[UpdateAddHtlc] =
    (localCommit.spec.htlcs.filter(htlc => htlc.direction == OUT && blockheight >= htlc.add.cltvExpiry) ++
      remoteCommit.spec.htlcs.filter(htlc => htlc.direction == IN && blockheight >= htlc.add.cltvExpiry) ++
      remoteNextCommitInfo.left.toOption.map(_.nextRemoteCommit.spec.htlcs.filter(htlc => htlc.direction == IN && blockheight >= htlc.add.cltvExpiry)).getOrElse(Set.empty[DirectedHtlc])).map(_.add)

  def announceChannel: Boolean = (channelFlags & 0x01) != 0

  // TODO subtract the pushMe value from the balance?
  def availableBalanceForSendMsat: Long = {
    val reduced = CommitmentSpec.reduce(remoteCommit.spec, remoteChanges.acked, localChanges.proposed)
    val feesMsat = if (localParams.isFunder) Transactions.commitTxFee(Satoshi(remoteParams.dustLimitSatoshis), reduced)(commitmentContext = getContext).amount * 1000 else 0
    reduced.toRemoteMsat - remoteParams.channelReserveSatoshis * 1000 - feesMsat
  }

  /**
    *
    * ADDITIONS
    *
    */

  def specs2String: String = {
    s"""(${getContext}) specs:
       |localcommit:
       |  toLocal: ${localCommit.spec.toLocalMsat}
       |  toRemote: $localCommit.spec.toRemoteMsat}
       |  htlcs:
       |${localCommit.spec.htlcs.map(h => s"    ${h.direction} ${h.add.id} ${h.add.cltvExpiry}").mkString("\n")}
       |remotecommit:
       |  toLocal: ${remoteCommit.spec.toLocalMsat}
       |  toRemote: ${remoteCommit.spec.toRemoteMsat}
       |  htlcs:
       |${remoteCommit.spec.htlcs.map(h => s"    ${h.direction} ${h.add.id} ${h.add.cltvExpiry}").mkString("\n")}
       |next remotecommit:
       |  toLocal: ${remoteNextCommitInfo.left.toOption.map(_.nextRemoteCommit.spec.toLocalMsat).getOrElse("N/A")}
       |  toRemote: ${remoteNextCommitInfo.left.toOption.map(_.nextRemoteCommit.spec.toRemoteMsat).getOrElse("N/A")}
       |  htlcs:
       |${remoteNextCommitInfo.left.toOption.map(_.nextRemoteCommit.spec.htlcs.map(h => s"    ${h.direction} ${h.add.id} ${h.add.cltvExpiry}").mkString("\n")).getOrElse("N/A")}""".stripMargin
  }

  def changes2String: String = {
    s"""(${getContext}) commitments:
       |    localChanges:
       |        proposed: ${localChanges.proposed.map(msg2String(_)).mkString(" ")}
       |        signed: ${localChanges.signed.map(msg2String(_)).mkString(" ")}
       |        acked: ${localChanges.acked.map(msg2String(_)).mkString(" ")}
       |    remoteChanges:
       |        proposed: ${remoteChanges.proposed.map(msg2String(_)).mkString(" ")}
       |        acked: ${remoteChanges.acked.map(msg2String(_)).mkString(" ")}
       |        signed: ${remoteChanges.signed.map(msg2String(_)).mkString(" ")}
       |    nextHtlcId:
       |        local: $localNextHtlcId
       |        remote: $remoteNextHtlcId""".stripMargin
  }

  /**
    *
    * @param cmd add HTLC command
    * @return either Left(failure, error message) where failure is a failure message (see BOLT #4 and the Failure Message class) or Right((new commitments, updateAddHtlc)
    */
  def sendAdd(cmd: CMD_ADD_HTLC, origin: Origin): Either[ChannelException, (Commitments, UpdateAddHtlc)] = {
    if (cmd.paymentHash.size != 32) {
      return Left(InvalidPaymentHash(channelId))
    }

    val blockCount = Globals.blockCount.get()
    // our counterparty needs a reasonable amount of time to pull the funds from downstream before we can get refunded (see BOLT 2 and BOLT 11 for a calculation and rationale)
    val minExpiry = blockCount + Channel.MIN_CLTV_EXPIRY
    if (cmd.cltvExpiry < minExpiry) {
      return Left(ExpiryTooSmall(channelId, minimum = minExpiry, actual = cmd.cltvExpiry, blockCount = blockCount))
    }
    val maxExpiry = blockCount + Channel.MAX_CLTV_EXPIRY
    // we don't want to use too high a refund timeout, because our funds will be locked during that time if the payment is never fulfilled
    if (cmd.cltvExpiry >= maxExpiry) {
      return Left(ExpiryTooBig(channelId, maximum = maxExpiry, actual = cmd.cltvExpiry, blockCount = blockCount))
    }

    if (cmd.amountMsat < remoteParams.htlcMinimumMsat) {
      return Left(HtlcValueTooSmall(channelId, minimum = remoteParams.htlcMinimumMsat, actual = cmd.amountMsat))
    }

    // let's compute the current commitment *as seen by them* with this change taken into account
    val add = UpdateAddHtlc(channelId, localNextHtlcId, cmd.amountMsat, cmd.paymentHash, cmd.cltvExpiry, cmd.onion)
    // we increment the local htlc index and add an entry to the origins map
    val commitments1 = addLocalProposal(add) match {
      case c: CommitmentsV1 => c.copy(localNextHtlcId = localNextHtlcId + 1, originChannels = originChannels + (add.id -> origin))
      case s: SimplifiedCommitment => s.copy(localNextHtlcId = localNextHtlcId + 1, originChannels = originChannels + (add.id -> origin))
    }
    // we need to base the next current commitment on the last sig we sent, even if we didn't yet receive their revocation
    val remoteCommit1 = commitments1.remoteNextCommitInfo.left.toOption.map(_.nextRemoteCommit).getOrElse(commitments1.remoteCommit)
    val reduced = CommitmentSpec.reduce(remoteCommit1.spec, commitments1.remoteChanges.acked, commitments1.localChanges.proposed)
    // the HTLC we are about to create is outgoing, but from their point of view it is incoming
    val outgoingHtlcs = reduced.htlcs.filter(_.direction == IN)

    val htlcValueInFlight = UInt64(outgoingHtlcs.map(_.add.amountMsat).sum)
    if (htlcValueInFlight > commitments1.remoteParams.maxHtlcValueInFlightMsat) {
      // TODO: this should be a specific UPDATE error
      return Left(HtlcValueTooHighInFlight(channelId, maximum = commitments1.remoteParams.maxHtlcValueInFlightMsat, actual = htlcValueInFlight))
    }

    if (outgoingHtlcs.size > commitments1.remoteParams.maxAcceptedHtlcs) {
      return Left(TooManyAcceptedHtlcs(channelId, maximum = commitments1.remoteParams.maxAcceptedHtlcs))
    }

    // a node cannot spend pending incoming htlcs, and need to keep funds above the reserve required by the counterparty, after paying the fee
    // we look from remote's point of view, so if local is funder remote doesn't pay the fees
    val fees = if (commitments1.localParams.isFunder) Transactions.commitTxFee(Satoshi(commitments1.remoteParams.dustLimitSatoshis), reduced)(getContext).amount else 0
    val missing = reduced.toRemoteMsat / 1000 - commitments1.remoteParams.channelReserveSatoshis - fees
    if (missing < 0) {
      return Left(InsufficientFunds(channelId, amountMsat = cmd.amountMsat, missingSatoshis = -1 * missing, reserveSatoshis = commitments1.remoteParams.channelReserveSatoshis, feesSatoshis = fees))
    }

    Right(commitments1, add)
  }

  def receiveAdd(add: UpdateAddHtlc): Commitments = {
    if (add.id != remoteNextHtlcId) {
      throw UnexpectedHtlcId(channelId, expected = remoteNextHtlcId, actual = add.id)
    }

    if (add.paymentHash.size != 32) {
      throw InvalidPaymentHash(channelId)
    }

    if (add.amountMsat < localParams.htlcMinimumMsat) {
      throw HtlcValueTooSmall(channelId, minimum = localParams.htlcMinimumMsat, actual = add.amountMsat)
    }

    // let's compute the current commitment *as seen by us* including this change
    val commitments1 = addRemoteProposal(add) match {
      case c: CommitmentsV1 => c.copy(remoteNextHtlcId = remoteNextHtlcId + 1)
      case s: SimplifiedCommitment => s.copy(remoteNextHtlcId = remoteNextHtlcId + 1)
    }
    val reduced = CommitmentSpec.reduce(commitments1.localCommit.spec, commitments1.localChanges.acked, commitments1.remoteChanges.proposed)
    val incomingHtlcs = reduced.htlcs.filter(_.direction == IN)

    val htlcValueInFlight = UInt64(incomingHtlcs.map(_.add.amountMsat).sum)
    if (htlcValueInFlight > commitments1.localParams.maxHtlcValueInFlightMsat) {
      throw HtlcValueTooHighInFlight(channelId, maximum = commitments1.localParams.maxHtlcValueInFlightMsat, actual = htlcValueInFlight)
    }

    if (incomingHtlcs.size > commitments1.localParams.maxAcceptedHtlcs) {
      throw TooManyAcceptedHtlcs(channelId, maximum = commitments1.localParams.maxAcceptedHtlcs)
    }

    // a node cannot spend pending incoming htlcs, and need to keep funds above the reserve required by the counterparty, after paying the fee
    val fees = if (commitments1.localParams.isFunder) 0 else Transactions.commitTxFee(Satoshi(commitments1.localParams.dustLimitSatoshis), reduced)(getContext).amount
    val missing = reduced.toRemoteMsat / 1000 - commitments1.localParams.channelReserveSatoshis - fees
    if (missing < 0) {
      throw InsufficientFunds(channelId, amountMsat = add.amountMsat, missingSatoshis = -1 * missing, reserveSatoshis = commitments1.localParams.channelReserveSatoshis, feesSatoshis = fees)
    }

    commitments1
  }

  def getHtlcCrossSigned(directionRelativeToLocal: Direction, htlcId: Long): Option[UpdateAddHtlc] = {
    val remoteSigned = localCommit.spec.htlcs.find(htlc => htlc.direction == directionRelativeToLocal && htlc.add.id == htlcId)
    val localSigned = remoteNextCommitInfo.left.toOption.map(_.nextRemoteCommit).getOrElse(remoteCommit)
      .spec.htlcs.find(htlc => htlc.direction == directionRelativeToLocal.opposite && htlc.add.id == htlcId)
    for {
      htlc_out <- remoteSigned
      htlc_in <- localSigned
    } yield htlc_in.add
  }

  def sendFulfill(cmd: CMD_FULFILL_HTLC): (Commitments, UpdateFulfillHtlc) =
    getHtlcCrossSigned(IN, cmd.id) match {
      case Some(htlc) if localChanges.proposed.exists {
        case u: UpdateFulfillHtlc if htlc.id == u.id => true
        case u: UpdateFailHtlc if htlc.id == u.id => true
        case u: UpdateFailMalformedHtlc if htlc.id == u.id => true
        case _ => false
      } =>
        // we have already sent a fail/fulfill for this htlc
        throw UnknownHtlcId(channelId, cmd.id)
      case Some(htlc) if htlc.paymentHash == sha256(cmd.r) =>
        val fulfill = UpdateFulfillHtlc(channelId, cmd.id, cmd.r)
        val commitments1 = addLocalProposal(fulfill)
        (commitments1, fulfill)
      case Some(htlc) => throw InvalidHtlcPreimage(channelId, cmd.id)
      case None => throw UnknownHtlcId(channelId, cmd.id)
    }

  def receiveFulfill(fulfill: UpdateFulfillHtlc): Either[Commitments, (Commitments, Origin, UpdateAddHtlc)] =
    getHtlcCrossSigned(OUT, fulfill.id) match {
      case Some(htlc) if htlc.paymentHash == sha256(fulfill.paymentPreimage) => Right((addRemoteProposal(fulfill), originChannels(fulfill.id), htlc))
      case Some(htlc) => throw InvalidHtlcPreimage(channelId, fulfill.id)
      case None => throw UnknownHtlcId(channelId, fulfill.id)
    }

  def sendFail(cmd: CMD_FAIL_HTLC, nodeSecret: PrivateKey): (Commitments, UpdateFailHtlc) =
    getHtlcCrossSigned(IN, cmd.id) match {
      case Some(htlc) if localChanges.proposed.exists {
        case u: UpdateFulfillHtlc if htlc.id == u.id => true
        case u: UpdateFailHtlc if htlc.id == u.id => true
        case u: UpdateFailMalformedHtlc if htlc.id == u.id => true
        case _ => false
      } =>
        // we have already sent a fail/fulfill for this htlc
        throw UnknownHtlcId(channelId, cmd.id)
      case Some(htlc) =>
        // we need the shared secret to build the error packet
        Sphinx.parsePacket(nodeSecret, htlc.paymentHash, htlc.onionRoutingPacket).map(_.sharedSecret) match {
          case Success(sharedSecret) =>
            val reason = cmd.reason match {
              case Left(forwarded) => Sphinx.forwardErrorPacket(forwarded, sharedSecret)
              case Right(failure) => Sphinx.createErrorPacket(sharedSecret, failure)
            }
            val fail = UpdateFailHtlc(channelId, cmd.id, reason)
            val commitments1 = addLocalProposal(fail)
            (commitments1, fail)
          case Failure(_) => throw new CannotExtractSharedSecret(channelId, htlc)
        }
      case None => throw UnknownHtlcId(channelId, cmd.id)
    }

  def sendFailMalformed(cmd: CMD_FAIL_MALFORMED_HTLC): (Commitments, UpdateFailMalformedHtlc) = {
    // BADONION bit must be set in failure_code
    if ((cmd.failureCode & FailureMessageCodecs.BADONION) == 0) {
      throw InvalidFailureCode(channelId)
    }
    getHtlcCrossSigned(IN, cmd.id) match {
      case Some(htlc) if localChanges.proposed.exists {
        case u: UpdateFulfillHtlc if htlc.id == u.id => true
        case u: UpdateFailHtlc if htlc.id == u.id => true
        case u: UpdateFailMalformedHtlc if htlc.id == u.id => true
        case _ => false
      } =>
        // we have already sent a fail/fulfill for this htlc
        throw UnknownHtlcId(channelId, cmd.id)
      case Some(htlc) =>
        val fail = UpdateFailMalformedHtlc(channelId, cmd.id, cmd.onionHash, cmd.failureCode)
        val commitments1 = addLocalProposal(fail)
        (commitments1, fail)
      case None => throw UnknownHtlcId(channelId, cmd.id)
    }
  }

  def receiveFail(fail: UpdateFailHtlc): Either[Commitments, (Commitments, Origin, UpdateAddHtlc)] =
    getHtlcCrossSigned(OUT, fail.id) match {
      case Some(htlc) => Right((addRemoteProposal(fail), originChannels(fail.id), htlc))
      case None => throw UnknownHtlcId(channelId, fail.id)
    }

  def receiveFailMalformed(fail: UpdateFailMalformedHtlc): Either[Commitments, (Commitments, Origin, UpdateAddHtlc)] = {
    // A receiving node MUST fail the channel if the BADONION bit in failure_code is not set for update_fail_malformed_htlc.
    if ((fail.failureCode & FailureMessageCodecs.BADONION) == 0) {
      throw InvalidFailureCode(channelId)
    }

    getHtlcCrossSigned(OUT, fail.id) match {
      case Some(htlc) => Right((addRemoteProposal(fail), originChannels(fail.id), htlc))
      case None => throw UnknownHtlcId(channelId, fail.id)
    }
  }

  def sendFee(cmd: CMD_UPDATE_FEE): (Commitments, UpdateFee)

  def receiveFee(fee: UpdateFee, maxFeerateMismatch: Double): Commitments

  def localHasUnsignedOutgoingHtlcs: Boolean = localChanges.proposed.collectFirst { case u: UpdateAddHtlc => u }.isDefined

  def remoteHasUnsignedOutgoingHtlcs: Boolean = remoteChanges.proposed.collectFirst { case u: UpdateAddHtlc => u }.isDefined

  def localHasChanges: Boolean = remoteChanges.acked.size > 0 || localChanges.proposed.size > 0

  def remoteHasChanges: Boolean = localChanges.acked.size > 0 || remoteChanges.proposed.size > 0

  def sendCommit(keyManager: KeyManager)(implicit log: LoggingAdapter): (Commitments, CommitSig) = {
    remoteNextCommitInfo match {
      case Right(_) if !localHasChanges =>
        throw CannotSignWithoutChanges(channelId)
      case Right(remoteNextPerCommitmentPoint) =>
        // remote commitment will includes all local changes + remote acked changes
        val spec = CommitmentSpec.reduce(remoteCommit.spec, remoteChanges.acked, localChanges.proposed)
        val localPerCommitmentPoint = keyManager.commitmentPoint(localParams.channelKeyPath, localCommit.index + 1)
        val (remoteCommitTx, htlcTimeoutTxs, htlcSuccessTxs) = makeRemoteTxs(keyManager, remoteCommit.index + 1, localParams, remoteParams, commitInput, remoteNextPerCommitmentPoint, localPerCommitmentPoint, spec)(getContext)
        val sig = keyManager.sign(remoteCommitTx, keyManager.fundingPublicKey(localParams.channelKeyPath), SIGHASH_ALL)

        val sortedHtlcTxs: Seq[TransactionWithInputInfo] = (htlcTimeoutTxs ++ htlcSuccessTxs).sortBy(_.input.outPoint.index)
        val htlcSigs = getContext match {
          case ContextCommitmentV1 => sortedHtlcTxs.map(keyManager.sign(_, keyManager.htlcPoint(localParams.channelKeyPath), remoteNextPerCommitmentPoint, SIGHASH_ALL))
          case ContextSimplifiedCommitment => sortedHtlcTxs.map(keyManager.sign(_, keyManager.htlcPoint(localParams.channelKeyPath), remoteNextPerCommitmentPoint, SIGHASH_SINGLE | SIGHASH_ANYONECANPAY))
        }

        // NB: IN/OUT htlcs are inverted because this is the remote commit
        log.info(s"built remote commit number=${remoteCommit.index + 1} htlc_in={} htlc_out={} feeratePerKw=${spec.feeratePerKw} txid=${remoteCommitTx.tx.txid} tx={}", spec.htlcs.filter(_.direction == OUT).map(_.add.id).mkString(","), spec.htlcs.filter(_.direction == IN).map(_.add.id).mkString(","), remoteCommitTx.tx)

        // don't sign if they don't get paid
        val commitSig = CommitSig(
          channelId = channelId,
          signature = sig,
          htlcSignatures = htlcSigs.toList
        )

        val commitments1 = this match {
          case c: CommitmentsV1 => c.copy(
            remoteNextCommitInfo = Left(WaitingForRevocation(RemoteCommit(remoteCommit.index + 1, spec, remoteCommitTx.tx.txid, remoteNextPerCommitmentPoint), commitSig, localCommit.index)),
            localChanges = localChanges.copy(proposed = Nil, signed = localChanges.proposed),
            remoteChanges = remoteChanges.copy(acked = Nil, signed = remoteChanges.acked))
          case s: SimplifiedCommitment => s.copy(
            remoteNextCommitInfo = Left(WaitingForRevocation(RemoteCommit(remoteCommit.index + 1, spec, remoteCommitTx.tx.txid, remoteNextPerCommitmentPoint), commitSig, localCommit.index)),
            localChanges = localChanges.copy(proposed = Nil, signed = localChanges.proposed),
            remoteChanges = remoteChanges.copy(acked = Nil, signed = remoteChanges.acked))
        }

        (commitments1, commitSig)
      case Left(_) =>
        throw CannotSignBeforeRevocation(channelId)
    }
  }

  def receiveCommit(commit: CommitSig, keyManager: KeyManager)(implicit log: LoggingAdapter): (Commitments, RevokeAndAck) = {
    // they sent us a signature for *their* view of *our* next commit tx
    // so in terms of rev.hashes and indexes we have:
    // ourCommit.index -> our current revocation hash, which is about to become our old revocation hash
    // ourCommit.index + 1 -> our next revocation hash, used by *them* to build the sig we've just received, and which
    // is about to become our current revocation hash
    // ourCommit.index + 2 -> which is about to become our next revocation hash
    // we will reply to this sig with our old revocation hash preimage (at index) and our next revocation hash (at index + 1)
    // and will increment our index

    if (!remoteHasChanges)
      throw CannotSignWithoutChanges(channelId)

    // check that their signature is valid
    // signatures are now optional in the commit message, and will be sent only if the other party is actually
    // receiving money i.e its commit tx has one output for them

    val spec = CommitmentSpec.reduce(localCommit.spec, localChanges.acked, remoteChanges.proposed)
    val localPerCommitmentPoint = keyManager.commitmentPoint(localParams.channelKeyPath, localCommit.index + 1)
    val remotePerCommitmentPoint = remoteNextCommitInfo match {
      case Left(_) => remoteCommit.remotePerCommitmentPoint
      case Right(point) => point
    }

    val (localCommitTx, htlcTimeoutTxs, htlcSuccessTxs) = makeLocalTxs(keyManager, localCommit.index + 1, localParams, remoteParams, commitInput, localPerCommitmentPoint, remotePerCommitmentPoint, spec)(getContext)
    val sig = keyManager.sign(localCommitTx, keyManager.fundingPublicKey(localParams.channelKeyPath), SIGHASH_ALL)

    log.info(s"built local commit number=${localCommit.index + 1} htlc_in={} htlc_out={} feeratePerKw=${spec.feeratePerKw} txid=${localCommitTx.tx.txid} tx={}", spec.htlcs.filter(_.direction == IN).map(_.add.id).mkString(","), spec.htlcs.filter(_.direction == OUT).map(_.add.id).mkString(","), localCommitTx.tx)

    // TODO: should we have optional sig? (original comment: this tx will NOT be signed if our output is empty)

    // no need to compute htlc sigs if commit sig doesn't check out
    val signedCommitTx = Transactions.addSigs(localCommitTx, keyManager.fundingPublicKey(localParams.channelKeyPath).publicKey, remoteParams.fundingPubKey, sig, commit.signature)
    if (Transactions.checkSpendable(signedCommitTx).isFailure) {
      throw InvalidCommitmentSignature(channelId, signedCommitTx.tx)
    }

    val sortedHtlcTxs: Seq[TransactionWithInputInfo] = (htlcTimeoutTxs ++ htlcSuccessTxs).sortBy(_.input.outPoint.index)
    if (commit.htlcSignatures.size != sortedHtlcTxs.size) {
      throw HtlcSigCountMismatch(channelId, sortedHtlcTxs.size, commit.htlcSignatures.size)
    }
    val htlcSigs = getContext match {
      case ContextCommitmentV1 => sortedHtlcTxs.map(keyManager.sign(_, keyManager.htlcPoint(localParams.channelKeyPath), localPerCommitmentPoint, SIGHASH_ALL))
      case ContextSimplifiedCommitment => sortedHtlcTxs.map(keyManager.sign(_, keyManager.htlcPoint(localParams.channelKeyPath), localPerCommitmentPoint, SIGHASH_SINGLE | SIGHASH_ANYONECANPAY))
    }
    val remoteHtlcPubkey = Generators.derivePubKey(remoteParams.htlcBasepoint, localPerCommitmentPoint)
    // combine the sigs to make signed txes
    val htlcTxsAndSigs = (sortedHtlcTxs, htlcSigs, commit.htlcSignatures).zipped.toList.collect {
      case (htlcTx: HtlcTimeoutTx, localSig, remoteSig) =>
        if (Transactions.checkSpendable(Transactions.addSigs(htlcTx, localSig, remoteSig)).isFailure) {
          throw InvalidHtlcSignature(channelId, htlcTx.tx)
        }
        HtlcTxAndSigs(htlcTx, localSig, remoteSig)
      case (htlcTx: HtlcSuccessTx, localSig, remoteSig) if getContext == ContextCommitmentV1 =>
        // we can't check that htlc-success tx are spendable because we need the payment preimage; thus we only check the remote sig
        if (Transactions.checkSig(htlcTx, remoteSig, remoteHtlcPubkey, SIGHASH_ALL) == false) {
          throw InvalidHtlcSignature(channelId, htlcTx.tx)
        }
        HtlcTxAndSigs(htlcTx, localSig, remoteSig)
      case (htlcTx: HtlcSuccessTx, localSig, remoteSig) if getContext == ContextSimplifiedCommitment =>
        // we can't check that htlc-success tx are spendable because we need the payment preimage; thus we only check the remote sig
        if (Transactions.checkSig(htlcTx, remoteSig, remoteHtlcPubkey, SIGHASH_SINGLE | SIGHASH_ANYONECANPAY) == false) {
          throw InvalidHtlcSignature(channelId, htlcTx.tx)
        }
        HtlcTxAndSigs(htlcTx, localSig, remoteSig)
    }

    // we will send our revocation preimage + our next revocation hash
    val localPerCommitmentSecret = keyManager.commitmentSecret(localParams.channelKeyPath, localCommit.index)
    val localNextPerCommitmentPoint = keyManager.commitmentPoint(localParams.channelKeyPath, localCommit.index + 2)
    val revocation = RevokeAndAck(
      channelId = channelId,
      perCommitmentSecret = localPerCommitmentSecret,
      nextPerCommitmentPoint = localNextPerCommitmentPoint
    )

    // update our commitment data
    val localCommit1 = LocalCommit(
      index = localCommit.index + 1,
      spec,
      publishableTxs = PublishableTxs(signedCommitTx, htlcTxsAndSigs))
    val ourChanges1 = localChanges.copy(acked = Nil)
    val theirChanges1 = remoteChanges.copy(proposed = Nil, acked = remoteChanges.acked ++ remoteChanges.proposed)
    val commitments1 = this match {
      case c: CommitmentsV1 => c.copy(localCommit = localCommit1, localChanges = ourChanges1, remoteChanges = theirChanges1)
      case s: SimplifiedCommitment => s.copy(localCommit = localCommit1, localChanges = ourChanges1, remoteChanges = theirChanges1)
    }

    (commitments1, revocation)
  }


  def receiveRevocation(revocation: RevokeAndAck): (Commitments, Seq[ForwardMessage]) = {

    // we receive a revocation because we just sent them a sig for their next commit tx
    remoteNextCommitInfo match {
      case Left(_) if revocation.perCommitmentSecret.toPoint != remoteCommit.remotePerCommitmentPoint =>
        throw InvalidRevocation(channelId)
      case Left(WaitingForRevocation(theirNextCommit, _, _, _)) =>
        val forwards = remoteChanges.signed collect {
          // we forward adds downstream only when they have been committed by both sides
          // it always happen when we receive a revocation, because they send the add, then they sign it, then we sign it
          case add: UpdateAddHtlc => ForwardAdd(add)
          // same for fails: we need to make sure that they are in neither commitment before propagating the fail upstream
          case fail: UpdateFailHtlc =>
            val origin = originChannels(fail.id)
            val add = remoteCommit.spec.htlcs.find(p => p.direction == IN && p.add.id == fail.id).map(_.add).get
            ForwardFail(fail, origin, add)
          // same as above
          case fail: UpdateFailMalformedHtlc =>
            val origin = originChannels(fail.id)
            val add = remoteCommit.spec.htlcs.find(p => p.direction == IN && p.add.id == fail.id).map(_.add).get
            ForwardFailMalformed(fail, origin, add)
        }
        // the outgoing following htlcs have been completed (fulfilled or failed) when we received this revocation
        // they have been removed from both local and remote commitment
        // (since fulfill/fail are sent by remote, they are (1) signed by them, (2) revoked by us, (3) signed by us, (4) revoked by them
        val completedOutgoingHtlcs = remoteCommit.spec.htlcs.filter(_.direction == IN).map(_.add.id) -- theirNextCommit.spec.htlcs.filter(_.direction == IN).map(_.add.id)
        // we remove the newly completed htlcs from the origin map
        val originChannels1 = originChannels -- completedOutgoingHtlcs
        val commitments1 = this match {
          case c: CommitmentsV1 => c.copy(
            localChanges = localChanges.copy(signed = Nil, acked = localChanges.acked ++ localChanges.signed),
            remoteChanges = remoteChanges.copy(signed = Nil),
            remoteCommit = theirNextCommit,
            remoteNextCommitInfo = Right(revocation.nextPerCommitmentPoint),
            remotePerCommitmentSecrets = remotePerCommitmentSecrets.addHash(revocation.perCommitmentSecret, 0xFFFFFFFFFFFFL - remoteCommit.index),
            originChannels = originChannels1)
          case s: SimplifiedCommitment => s.copy(
            localChanges = localChanges.copy(signed = Nil, acked = localChanges.acked ++ localChanges.signed),
            remoteChanges = remoteChanges.copy(signed = Nil),
            remoteCommit = theirNextCommit,
            remoteNextCommitInfo = Right(revocation.nextPerCommitmentPoint),
            remotePerCommitmentSecrets = remotePerCommitmentSecrets.addHash(revocation.perCommitmentSecret, 0xFFFFFFFFFFFFL - remoteCommit.index),
            originChannels = originChannels1)
        }

        (commitments1, forwards)
      case Right(_) =>
        throw UnexpectedRevocation(channelId)
    }
  }


  // get the context for this commitment
  def getContext: CommitmentContext

}

// @formatter: off
sealed trait CommitmentContext

object ContextCommitmentV1 extends CommitmentContext

object ContextSimplifiedCommitment extends CommitmentContext

// @formatter: on

/**
  * about remoteNextCommitInfo:
  * we either:
  * - have built and signed their next commit tx with their next revocation hash which can now be discarded
  * - have their next per-commitment point
  * So, when we've signed and sent a commit message and are waiting for their revocation message,
  * theirNextCommitInfo is their next commit tx. The rest of the time, it is their next per-commitment point
  */
case class CommitmentsV1(localParams: LocalParams, remoteParams: RemoteParams,
                         channelFlags: Byte,
                         localCommit: LocalCommit, remoteCommit: RemoteCommit,
                         localChanges: LocalChanges, remoteChanges: RemoteChanges,
                         localNextHtlcId: Long, remoteNextHtlcId: Long,
                         originChannels: Map[Long, Origin], // for outgoing htlcs relayed through us, the id of the previous channel
                         remoteNextCommitInfo: Either[WaitingForRevocation, Point],
                         commitInput: InputInfo,
                         remotePerCommitmentSecrets: ShaChain, channelId: BinaryData) extends Commitments {

  override def getContext: CommitmentContext = ContextCommitmentV1

  override def addLocalProposal(proposal: UpdateMessage): Commitments = this.copy(localChanges = localChanges.copy(proposed = localChanges.proposed :+ proposal))

  override def addRemoteProposal(proposal: UpdateMessage): Commitments = this.copy(remoteChanges = remoteChanges.copy(proposed = remoteChanges.proposed :+ proposal))

  def sendFee(cmd: CMD_UPDATE_FEE): (Commitments, UpdateFee) = {
    if (!localParams.isFunder) {
      throw FundeeCannotSendUpdateFee(channelId)
    }

    // let's compute the current commitment *as seen by them* with this change taken into account
    val fee = UpdateFee(channelId, cmd.feeratePerKw)
    // update_fee replace each other, so we can remove previous ones
    val commitments1 = this.copy(localChanges = localChanges.copy(proposed = localChanges.proposed.filterNot(_.isInstanceOf[UpdateFee]) :+ fee))
    val reduced = CommitmentSpec.reduce(commitments1.remoteCommit.spec, commitments1.remoteChanges.acked, commitments1.localChanges.proposed)

    // a node cannot spend pending incoming htlcs, and need to keep funds above the reserve required by the counterparty, after paying the fee
    // we look from remote's point of view, so if local is funder remote doesn't pay the fees
    val fees = Transactions.commitTxFee(Satoshi(commitments1.remoteParams.dustLimitSatoshis), reduced)(getContext).amount // we update the fee only in NON simplified commitment
    val missing = reduced.toRemoteMsat / 1000 - commitments1.remoteParams.channelReserveSatoshis - fees
    if (missing < 0) {
      throw CannotAffordFees(channelId, missingSatoshis = -1 * missing, reserveSatoshis = commitments1.localParams.channelReserveSatoshis, feesSatoshis = fees)
    }

    (commitments1, fee)
  }

  def receiveFee(fee: UpdateFee, maxFeerateMismatch: Double): Commitments = {
    if (localParams.isFunder) {
      throw FundeeCannotSendUpdateFee(channelId)
    }

    if (fee.feeratePerKw < fr.acinq.eclair.MinimumFeeratePerKw) {
      throw FeerateTooSmall(channelId, remoteFeeratePerKw = fee.feeratePerKw)
    }

    val localFeeratePerKw = Globals.feeratesPerKw.get.blocks_2
    if (Helpers.isFeeDiffTooHigh(fee.feeratePerKw, localFeeratePerKw, maxFeerateMismatch)) {
      throw FeerateTooDifferent(channelId, localFeeratePerKw = localFeeratePerKw, remoteFeeratePerKw = fee.feeratePerKw)
    }

    // NB: we check that the funder can afford this new fee even if spec allows to do it at next signature
    // It is easier to do it here because under certain (race) conditions spec allows a lower-than-normal fee to be paid,
    // and it would be tricky to check if the conditions are met at signing
    // (it also means that we need to check the fee of the initial commitment tx somewhere)

    // let's compute the current commitment *as seen by us* including this change
    // update_fee replace each other, so we can remove previous ones
    val commitments1 = this.copy(remoteChanges = remoteChanges.copy(proposed = remoteChanges.proposed.filterNot(_.isInstanceOf[UpdateFee]) :+ fee))
    val reduced = CommitmentSpec.reduce(commitments1.localCommit.spec, commitments1.localChanges.acked, commitments1.remoteChanges.proposed)

    // a node cannot spend pending incoming htlcs, and need to keep funds above the reserve required by the counterparty, after paying the fee
    val fees = Transactions.commitTxFee(Satoshi(commitments1.remoteParams.dustLimitSatoshis), reduced)(getContext).amount // we update the fee only in NON simplified
    val missing = reduced.toRemoteMsat / 1000 - commitments1.localParams.channelReserveSatoshis - fees
    if (missing < 0) {
      throw CannotAffordFees(channelId, missingSatoshis = -1 * missing, reserveSatoshis = commitments1.localParams.channelReserveSatoshis, feesSatoshis = fees)
    }

    commitments1
  }
}


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

object Commitments {

  def revocationPreimage(seed: BinaryData, index: Long): BinaryData = ShaChain.shaChainFromSeed(seed, 0xFFFFFFFFFFFFFFFFL - index)

  def revocationHash(seed: BinaryData, index: Long): BinaryData = Crypto.sha256(revocationPreimage(seed, index))

  def makeLocalTxs(keyManager: KeyManager, commitTxNumber: Long, localParams: LocalParams, remoteParams: RemoteParams, commitmentInput: InputInfo, localPerCommitmentPoint: Point, remotePerCommitmentPoint: Point, spec: CommitmentSpec)(implicit commitmentContext: CommitmentContext): (CommitTx, Seq[HtlcTimeoutTx], Seq[HtlcSuccessTx]) = {
    val localDelayedPaymentPubkey = Generators.derivePubKey(keyManager.delayedPaymentPoint(localParams.channelKeyPath).publicKey, localPerCommitmentPoint)
    val localHtlcPubkey = Generators.derivePubKey(keyManager.htlcPoint(localParams.channelKeyPath).publicKey, localPerCommitmentPoint)

    val remotePaymentPubkey = commitmentContext match {
      case ContextSimplifiedCommitment => PublicKey(remoteParams.paymentBasepoint)
      case ContextCommitmentV1 => Generators.derivePubKey(remoteParams.paymentBasepoint, localPerCommitmentPoint)
    }
    val remoteDelayedPaymentPubkey = Generators.derivePubKey(remoteParams.delayedPaymentBasepoint, remotePerCommitmentPoint)
    val remoteHtlcPubkey = Generators.derivePubKey(remoteParams.htlcBasepoint, localPerCommitmentPoint)
    val localRevocationPubkey = Generators.revocationPubKey(remoteParams.revocationBasepoint, localPerCommitmentPoint)
    val commitTx = Transactions.makeCommitTx(commitmentInput, commitTxNumber, keyManager.paymentPoint(localParams.channelKeyPath).publicKey, remoteParams.paymentBasepoint, localParams.isFunder, Satoshi(localParams.dustLimitSatoshis), localRevocationPubkey, remoteParams.toSelfDelay, localDelayedPaymentPubkey, remotePaymentPubkey, localHtlcPubkey, remoteHtlcPubkey, remoteDelayedPaymentPubkey, spec)
    val (htlcTimeoutTxs, htlcSuccessTxs) = Transactions.makeHtlcTxs(commitTx.tx, Satoshi(localParams.dustLimitSatoshis), localRevocationPubkey, remoteParams.toSelfDelay, localDelayedPaymentPubkey, localHtlcPubkey, remoteHtlcPubkey, spec)
    (commitTx, htlcTimeoutTxs, htlcSuccessTxs)
  }

  def makeRemoteTxs(keyManager: KeyManager, commitTxNumber: Long, localParams: LocalParams, remoteParams: RemoteParams, commitmentInput: InputInfo, remotePerCommitmentPoint: Point, localPerCommitmentPoint: Point, spec: CommitmentSpec)(implicit commitmentContext: CommitmentContext): (CommitTx, Seq[HtlcTimeoutTx], Seq[HtlcSuccessTx]) = {
    val localPaymentPubkey = commitmentContext match {
      case ContextSimplifiedCommitment => keyManager.paymentPoint(localParams.channelKeyPath).publicKey
      case ContextCommitmentV1 => Generators.derivePubKey(keyManager.paymentPoint(localParams.channelKeyPath).publicKey, remotePerCommitmentPoint)
    }
    val localDelayedPaymentPubkey = Generators.derivePubKey(keyManager.delayedPaymentPoint(localParams.channelKeyPath).publicKey, localPerCommitmentPoint)
    val localHtlcPubkey = Generators.derivePubKey(keyManager.htlcPoint(localParams.channelKeyPath).publicKey, remotePerCommitmentPoint)
    val remoteDelayedPaymentPubkey = Generators.derivePubKey(remoteParams.delayedPaymentBasepoint, remotePerCommitmentPoint)
    val remoteHtlcPubkey = Generators.derivePubKey(remoteParams.htlcBasepoint, remotePerCommitmentPoint)
    val remoteRevocationPubkey = Generators.revocationPubKey(keyManager.revocationPoint(localParams.channelKeyPath).publicKey, remotePerCommitmentPoint)
    val commitTx = Transactions.makeCommitTx(commitmentInput, commitTxNumber, remoteParams.paymentBasepoint, keyManager.paymentPoint(localParams.channelKeyPath).publicKey, !localParams.isFunder, Satoshi(remoteParams.dustLimitSatoshis), remoteRevocationPubkey, localParams.toSelfDelay, remoteDelayedPaymentPubkey, localPaymentPubkey, remoteHtlcPubkey, localHtlcPubkey, localDelayedPaymentPubkey, spec)
    val (htlcTimeoutTxs, htlcSuccessTxs) = Transactions.makeHtlcTxs(commitTx.tx, Satoshi(remoteParams.dustLimitSatoshis), remoteRevocationPubkey, localParams.toSelfDelay, remoteDelayedPaymentPubkey, remoteHtlcPubkey, localHtlcPubkey, spec)
    (commitTx, htlcTimeoutTxs, htlcSuccessTxs)
  }

  def msg2String(msg: LightningMessage): String = msg match {
    case u: UpdateAddHtlc => s"add-${u.id}"
    case u: UpdateFulfillHtlc => s"ful-${u.id}"
    case u: UpdateFailHtlc => s"fail-${u.id}"
    case _: UpdateFee => s"fee"
    case _: CommitSig => s"sig"
    case _: RevokeAndAck => s"rev"
    case _: Error => s"err"
    case _: FundingLocked => s"funding_locked"
    case _ => "???"
  }
}


