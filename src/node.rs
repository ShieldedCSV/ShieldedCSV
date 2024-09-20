use crate::primitives::{Commitment, PublicKey, SigCommitment, Signature, ToSAccM, ToSAccValue};
use crate::{AggregateNullifier, BlockchainLocation, Coin, EdgeLabel, PCDVerKey, PCD};
use secp256k1::SecretKey;
use std::collections::HashMap;

pub struct Node {
    acct_id: SecretKey,
    nullifier_kv: HashMap<PublicKey, (SigCommitment, BlockchainLocation, Commitment)>,
    nullifier_accum: ToSAccM,
    nullifier_accum_history: Vec<ToSAccValue>,
}

impl Node {
    // Process a new block containing aggregate nullifiers at the given height.
    // Note that this function does not support blockchain reorganizations.
    pub fn process_block(
        mut self,
        blockheight: u64,
        aggregate_nullifiers: Vec<AggregateNullifier>,
    ) {
        let msg = secp256k1::Message::from_digest_slice(
            &format!("Shielded CSV: state update").as_bytes(),
        )
        .unwrap();
        let mut loc = blockheight * 2u64.pow(24);
        let mut block_nullifiers: Vec<(PublicKey, SigCommitment, BlockchainLocation, Commitment)> =
            Vec::new();
        for aggregate_nullifier in aggregate_nullifiers {
            // Zip public keys and messages
            let pm_aggd = aggregate_nullifier
                .clone()
                .pks
                .into_iter()
                .zip(std::iter::repeat(msg))
                .collect::<Vec<(PublicKey, secp256k1::Message)>>();
            if !Signature::agg_verify(&aggregate_nullifier.sig, pm_aggd) {
                continue;
            }
            for (i, pk) in aggregate_nullifier.pks.into_iter().enumerate() {
                if !self.nullifier_kv.contains_key(&pk) {
                    let blockchain_loc = loc.to_be_bytes()[..6].try_into().unwrap();
                    // sig_comm commits to the tx_hash
                    let sig_comm = Signature::commit_retrieve(&aggregate_nullifier.sig, i);
                    self.nullifier_kv.insert(
                        pk,
                        (sig_comm, blockchain_loc, aggregate_nullifier.fee_acct_comm.clone()),
                    );
                    loc += 1;
                    block_nullifiers.push((
                        pk,
                        sig_comm,
                        blockchain_loc,
                        aggregate_nullifier.fee_acct_comm.clone(),
                    ));
                }
            }
        }
        self.nullifier_accum = ToSAccM::append_set(&self.nullifier_accum, block_nullifiers);
        self.nullifier_accum_history.push(ToSAccM::value(&self.nullifier_accum));
    }

    // A possible function for checking acceptance of a payment. If the coin is
    // valid, return the received amount.
    pub fn accept_payment(
        self,
        vk: &PCDVerKey,
        pk_commit_rand: &[u8; 32],
        coin: Coin,
        already_received_coins: Vec<[u8; 8]>,
        coin_proof: Vec<u8>,
    ) -> u64 {
        if coin.essence.address != Commitment::commit(&self.acct_id.secret_bytes(), pk_commit_rand)
        {
            return 0;
        }
        // Need to make sure that the accounts spent accum does not already
        // contain the blockchain_loc.
        if already_received_coins.contains(&coin.on_chain_id()) {
            return 0;
        }
        if !self.nullifier_accum_history.contains(&coin.nullifier_accum) {
            return 0;
        }
        if !PCD::verify(vk, EdgeLabel::Coin(coin), &coin_proof) {
            return 0;
        }
        return coin.essence.amount;
    }
}
