//! This crate accompanies the Shielded CSV paper, defines the PCD compliance
//! predicate and implements the protocol-specific components of a Shielded CSV
//! node.

pub mod node;
pub mod primitives;

use primitives::*;

// Aggregate nullifiers are posted to the blockchain by "publishers"
#[derive(Debug, PartialEq, Clone)]
pub struct AggregateNullifier {
    // Each public key commits to an account update
    pub pks: Vec<PublicKey>,
    // The "R-parts" of the half-aggregate signature commits to the transaction hash
    pub sig: Signature,
    // Commitment to the account ID of the publisher that will receive the fee
    pub fee_acct_comm: Commitment,
}

// The "essence" of a coin misses "context" information that can only be
// obtained once the creation of the coin is committed in the blockchain.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct CoinEssence {
    pub address: Commitment,
    pub amount: u64,
    // Index of the coin in a transaction
    pub idx: [u8; 2],
}

impl CoinEssence {
    // Index of the coin paying for fees in a transaction
    const FEE_IDX: [u8; 2] = [0xff, 0xff];
}

// The coin ID is the hash of the transaction creating the coin concatenated
// with the coin's index in the transaction
type CoinID = [u8; 34];

// Identifies nullifiers in the blockchain
// 21 bits for the block number (40 years)
// 22 bits to identify the nullifier in a block (as math.log(4M, 2) = 21.93)
type BlockchainLocation = [u8; 6];

// The on-chain coin ID is the blockchain location of the nullifier creating the
// coin concatenated with the coin's index in the transaction. This ID may
// change in a blockchain reorganization.
type CoinIDOnChain = [u8; 8];

// A coin given to the payment recipient, containing the coin's essence and
// context information required to verify the coin and spend it.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Coin {
    pub essence: CoinEssence,
    // Hash of the transaction that created the coin
    pub tx_hash: [u8; 32],
    // Location of the nullifier that created the coin in the blockchain
    pub blockchain_loc: BlockchainLocation,
    // The nullifier accumulator value this coin claims to be valid for
    pub nullifier_accum: ToSAccValue,
}

impl Coin {
    pub fn id(&self) -> CoinID {
        [self.tx_hash.as_slice(), self.essence.idx.as_slice()].concat().try_into().unwrap()
    }
    pub fn on_chain_id(&self) -> CoinIDOnChain {
        // return blockchain_loc || coin_idx
        [self.blockchain_loc.as_slice(), self.essence.idx.as_slice()].concat().try_into().unwrap()
    }
}

// The "essence" of an account state misses "context" information that can only
// be obtained once the creation of the account state is committed in the
// blockchain.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct AcctStateEssence {
    // Static identifier of the account
    pub id: PublicKey,
    pub balance: u64,
    // Public key that nullifies this state
    pub nullifier_pk: PublicKey,
}

// An account state containing the essence and context information required to
// prove the update of this account state.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct AcctState {
    pub essence: AcctStateEssence,
    // Contains coins that have already been spent
    pub spent_accum: AccValue,
    // The nullifier accumulator value this account state claims to be valid for
    pub nullifier_accum: ToSAccValue,
}

pub struct Transaction {
    // Conditional nullifier accumulator value: if this value is not a prefix of
    // the best blockchain's nullifier accumulator value, the account owner can
    // prove a no-op instead of this transaction.
    conditional_nav: ToSAccValue,
    prev_state: AcctStateEssence,
    prev_coins: Vec<CoinID>,
    new_state: AcctStateEssence,
    new_coins: Vec<CoinEssence>,
}

impl Transaction {
    pub fn hash(&self, randomness: [u8; 32]) -> [u8; 32] {
        // TODO: define this hash properly!
        let tx: Vec<u8> = format!(
            "{:?} {:?} {:?} {:?} {:?} {:?}",
            randomness,
            self.conditional_nav,
            self.prev_state,
            self.prev_coins,
            self.new_state,
            self.new_coins
        )
        .into_bytes();
        return hash(&tx);
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PaymentInitLocalInput {
    // TODO: account ID is unneeded unless account creation
    pub acct_id: PublicKey,
    // Randomness to open account ID commitments ("addresses") used in the coins
    // being spent
    pub acct_comm_rands: Vec<[u8; 32]>,
    pub new_coins: Vec<CoinEssence>,
    pub fee: u64,
    pub new_spent_accum: AccValue,
    // Spent non-membership and insertion proof
    pub snmi_proof: Vec<u8>,
    // Nullifier public key  used for the next account state update
    pub new_nullifier_pk: PublicKey,
    // Conditional nullifier accumulator value committed to in the transaction
    pub conditional_nav: ToSAccValue,
    // Randomness to be included in the tx_hash. This is necessary because
    // receivers obtain the transaction hash, but must not gain any information
    // about the transaction from the hash.
    pub tx_hash_randomness: [u8; 32],
    // The public key such that nullifier_tx_comm = p2c_commit(nullifier_tx_comm_pk, tx_hash)
    pub nullifier_tx_comm_pk: PublicKey,
    pub nullifier_tx_comm: SigCommitment,
    pub nullifier_accum: ToSAccValue,
    // Nullifier accumulator prefix proof
    pub nap_proof: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct PaymentInitOutputPartial {
    tx_hash: [u8; 32],
    nullifier_pk: PublicKey,
    nullifier_tx_comm: SigCommitment,
    nullifier_accum: ToSAccValue,
}

// Output of the payment_init predicate that is input to the payment_finalize predicate
#[derive(Debug, PartialEq, Clone)]
pub struct PaymentInitOutput {
    partial_output: PaymentInitOutputPartial,
    acct_state_essence: AcctStateEssence,
    spent_accum: AccValue,
    coin_essences: Vec<CoinEssence>,
}

// Output of the payment_init predicate that is input to the payment_finalize_fee predicate
#[derive(Debug, PartialEq, Clone)]
pub struct PaymentInitOutputFee {
    partial_output: PaymentInitOutputPartial,
    fee: u64,
}

pub fn payment_init(
    prev_state: AcctState,
    prev_coins: &[Coin],
    w_loc: PaymentInitLocalInput,
) -> Option<(PaymentInitOutput, PaymentInitOutputFee)> {
    // Check that this account is allowed to spend
    for (prev_coin, acct_comm_rand) in prev_coins.iter().zip(w_loc.acct_comm_rands.iter()) {
        if prev_coin.essence.address
            != Commitment::commit(&prev_state.essence.id.serialize(), &acct_comm_rand)
        {
            return None;
        }
    }

    // Check conservation of money
    // But when summing we need to make sure that the coin amounts do not
    // overflow.
    let mut coins_sum = 0u64;
    for coin in &w_loc.new_coins {
        match coins_sum.checked_add(coin.amount) {
            None => return None,
            Some(x) => coins_sum = x,
        }
    }
    match coins_sum.checked_sub(w_loc.fee) {
        None => return None,
        Some(x) => coins_sum = x,
    }
    let prev_coins_sum: u64 = prev_coins.iter().map(|x| x.essence.amount).sum();
    let new_balance;
    match (prev_state.essence.balance + prev_coins_sum).checked_sub(coins_sum) {
        None => return None,
        Some(x) => new_balance = x,
    }

    // Check that the prev_coins are not included in prev_state.spent_accum and
    // that w_loc.spent_accum is exactly prev_state.spent_accum with coins
    // included.
    let prev_coin_ids: Vec<[u8; 8]> = prev_coins.iter().map(|x| x.on_chain_id()).collect();
    if !AccV::verify_non_membership_and_insert(
        &prev_state.spent_accum,
        &w_loc.new_spent_accum,
        prev_coin_ids,
        &w_loc.snmi_proof,
    ) {
        return None;
    }

    // Check that the indices of new_coins are unique and within range
    let new_coin_idcs: Vec<[u8; 2]> = w_loc.new_coins.iter().map(|x| x.idx).collect();
    for i in 1..new_coin_idcs.len() {
        let idx = new_coin_idcs[i];
        if idx <= new_coin_idcs[i - 1] || idx == CoinEssence::FEE_IDX {
            return None;
        }
    }

    let acct_state_essence = AcctStateEssence {
        id: prev_state.essence.id,
        nullifier_pk: w_loc.new_nullifier_pk,
        balance: new_balance,
    };

    // Check that the transaction is committed in the nullifier
    let tx = Transaction {
        conditional_nav: w_loc.conditional_nav,
        prev_state: prev_state.essence,
        prev_coins: prev_coins.iter().map(|x| x.id()).collect(),
        new_state: acct_state_essence,
        new_coins: w_loc.new_coins.clone(),
    };
    let tx_hash = tx.hash(w_loc.tx_hash_randomness);
    if !Signature::commit_verify(w_loc.nullifier_tx_comm, &tx_hash, &w_loc.nullifier_tx_comm_pk) {
        return None;
    }

    let partial_output = PaymentInitOutputPartial {
        tx_hash,
        nullifier_pk: prev_state.essence.nullifier_pk,
        nullifier_tx_comm: w_loc.nullifier_tx_comm,
        nullifier_accum: w_loc.nullifier_accum,
    };

    // If the conditional_nav is not a prefix of the given nullifier
    // accumulator, this account update is essentially a no-op
    if ToSAccV::verify_distinct_element(
        &tx.conditional_nav,
        &w_loc.nullifier_accum,
        &w_loc.nap_proof,
    ) {
        let acct_state_essence = AcctStateEssence {
            id: acct_state_essence.id,
            nullifier_pk: acct_state_essence.nullifier_pk,
            balance: prev_state.essence.balance,
        };
        Some((
            PaymentInitOutput {
                partial_output,
                acct_state_essence,
                spent_accum: prev_state.spent_accum,
                coin_essences: Vec::new(),
            },
            PaymentInitOutputFee { partial_output, fee: 0 },
        ))
    } else {
        // Check that the prev_state, prev_coin and conditional tx nullifier
        // accumulators are prefixes of the given accumulator
        let mut nullifier_accums: Vec<ToSAccValue> =
            prev_coins.iter().map(|x| x.nullifier_accum).collect();
        nullifier_accums.push(prev_state.nullifier_accum);
        nullifier_accums.push(tx.conditional_nav);
        if !ToSAccV::verify_is_prefix(&nullifier_accums, &w_loc.nullifier_accum, &w_loc.nap_proof) {
            return None;
        }
        Some((
            PaymentInitOutput {
                partial_output,
                acct_state_essence,
                spent_accum: w_loc.new_spent_accum,
                coin_essences: w_loc.new_coins[1..].to_vec(),
            },
            PaymentInitOutputFee { partial_output, fee: w_loc.fee },
        ))
    }
}

// Predicate when creating a new account
pub fn payment_init_newacct(
    prev_coins: &[Coin],
    w_loc: PaymentInitLocalInput,
) -> Option<(PaymentInitOutput, PaymentInitOutputFee)> {
    let newacct = AcctState {
        essence: AcctStateEssence { id: w_loc.acct_id, nullifier_pk: w_loc.acct_id, balance: 0 },
        spent_accum: AccV::new(),
        nullifier_accum: w_loc.nullifier_accum,
    };
    payment_init(newacct, prev_coins, w_loc)
}

#[derive(Debug, PartialEq, Clone)]
pub struct PaymentFinalizeLocalInput {
    pub fee_acct_comm: Commitment,
    pub blockchain_loc: BlockchainLocation,
    pub nullifier_accum: ToSAccValue,
    // Nullifier membership proof
    pub nm_proof: Vec<u8>,
    // Nullifier accumulator prefix proof
    pub nap_proof: Vec<u8>,
}

pub fn payment_finalize_internal(
    pay_init_output: &PaymentInitOutputPartial,
    w_loc: &PaymentFinalizeLocalInput,
) -> bool {
    if !ToSAccV::verify_is_prefix(
        &[pay_init_output.nullifier_accum],
        &w_loc.nullifier_accum,
        &w_loc.nap_proof,
    ) {
        return false;
    }
    // Check that the tuple of `(nullifier_pk, nullifier_tx_comm,
    // blockchain_loc, fee_acct_comm)` corresponding to the account state is in
    // the nullifier accumulator
    if !ToSAccV::verify_union_membership(
        &w_loc.nullifier_accum,
        (
            pay_init_output.nullifier_pk,
            pay_init_output.nullifier_tx_comm,
            w_loc.blockchain_loc,
            w_loc.fee_acct_comm,
        ),
        &w_loc.nm_proof,
    ) {
        return false;
    }
    return true;
}

pub fn payment_finalize_fee(
    pay_init: &PaymentInitOutputFee,
    w_loc: PaymentFinalizeLocalInput,
) -> Option<Coin> {
    if !payment_finalize_internal(&pay_init.partial_output, &w_loc) {
        return None;
    }
    let coin = Coin {
        essence: CoinEssence {
            address: w_loc.fee_acct_comm,
            amount: pay_init.fee,
            idx: CoinEssence::FEE_IDX,
        },
        tx_hash: pay_init.partial_output.tx_hash,
        nullifier_accum: w_loc.nullifier_accum,
        blockchain_loc: w_loc.blockchain_loc,
    };
    Some(coin)
}

pub fn payment_finalize(
    pay_init: &PaymentInitOutput,
    w_loc: PaymentFinalizeLocalInput,
) -> Option<(AcctState, Vec<Coin>)> {
    if !payment_finalize_internal(&pay_init.partial_output, &w_loc) {
        return None;
    }
    // Enrich coin essences to obtain Coins
    let coins = pay_init
        .coin_essences
        .iter()
        .map(|x| Coin {
            essence: *x,
            tx_hash: pay_init.partial_output.tx_hash,
            nullifier_accum: w_loc.nullifier_accum,
            blockchain_loc: w_loc.blockchain_loc,
        })
        .collect();

    Some((
        AcctState {
            essence: pay_init.acct_state_essence,
            spent_accum: pay_init.spent_accum,
            nullifier_accum: w_loc.nullifier_accum,
        },
        coins,
    ))
}

#[derive(Debug, PartialEq)]
pub struct IssuanceProof {
    // TODO
}

pub fn issuance(w_loc: IssuanceProof) -> Option<Coin> {
    let _issuance_proof = w_loc;
    // This should check that the coin has been correctly issued.
    return None;
}

#[derive(Debug, PartialEq)]
pub enum LocalInput {
    Issuance(IssuanceProof),
    PaymentInit(PaymentInitLocalInput),
    PaymentFinalize(PaymentFinalizeLocalInput),
}

#[derive(Debug, PartialEq, Clone)]
pub enum EdgeLabel {
    AcctState(AcctState),
    Coin(Coin),
    PaymentInitOutput(PaymentInitOutput),
    PaymentInitOutputFee(PaymentInitOutputFee),
}

pub fn compliance_predicate_pay_init(
    z_out: EdgeLabel,
    w_loc: LocalInput,
    acct_state: Option<AcctState>,
    z_in: &[EdgeLabel],
) -> bool {
    let w_loc = if let LocalInput::PaymentInit(w_loc) = w_loc {
        w_loc
    } else {
        return false;
    };
    // Convert all z_ins to Coins
    let prev_coins: Result<Vec<Coin>, bool> = z_in.iter().try_fold(Vec::new(), |mut acc, x| {
        if let EdgeLabel::Coin(coin) = x {
            acc.push(*coin);
            Ok(acc)
        } else {
            Err(false)
        }
    });
    if let Err(_) = prev_coins {
        return false;
    }
    let prev_coins = prev_coins.unwrap();

    let output = if let Some(acct_state) = acct_state {
        payment_init(acct_state, &prev_coins, w_loc)
    } else {
        payment_init_newacct(&prev_coins, w_loc)
    };

    match output {
        None => return false,
        Some(output) => match z_out {
            EdgeLabel::PaymentInitOutput(z_out) => return output.0 == z_out,
            EdgeLabel::PaymentInitOutputFee(z_out) => return output.1 == z_out,
            _ => return false,
        },
    }
}

pub fn compliance_predicate_pay_finalize(
    z_out: EdgeLabel,
    w_loc: LocalInput,
    z_in: &[EdgeLabel],
) -> bool {
    if z_in.len() != 1 {
        return false;
    }
    let w_loc = if let LocalInput::PaymentFinalize(w_loc) = w_loc { w_loc } else { return false };
    match &z_in[0] {
        EdgeLabel::PaymentInitOutput(output) => {
            match payment_finalize(output, w_loc) {
                None => return false,
                Some((acct_state, coins)) => {
                    // z_out is either acct_state or contained in coins
                    return z_out == EdgeLabel::AcctState(acct_state)
                        || coins.iter().any(|x| z_out == EdgeLabel::Coin(*x));
                }
            }
        }
        EdgeLabel::PaymentInitOutputFee(output) => match payment_finalize_fee(output, w_loc) {
            None => return false,
            Some(coin) => return EdgeLabel::Coin(coin) == z_out,
        },
        _ => return false,
    }
}

pub fn compliance_predicate(z_out: EdgeLabel, w_loc: LocalInput, z_in: &[EdgeLabel]) -> bool {
    if z_in.len() == 0 {
        if let LocalInput::Issuance(w_loc) = w_loc {
            let coin = issuance(w_loc);
            if let Some(coin) = coin {
                return z_out == EdgeLabel::Coin(coin);
            }
        }
        return false;
    }

    match &z_in[0] {
        EdgeLabel::AcctState(acct_state) => {
            return compliance_predicate_pay_init(z_out, w_loc, Some(*acct_state), &z_in[1..])
        }
        EdgeLabel::Coin(_) => return compliance_predicate_pay_init(z_out, w_loc, None, z_in),
        EdgeLabel::PaymentInitOutput(_) => {
            return compliance_predicate_pay_finalize(z_out, w_loc, z_in)
        }
        EdgeLabel::PaymentInitOutputFee(_) => {
            return compliance_predicate_pay_finalize(z_out, w_loc, z_in)
        }
    }
}
