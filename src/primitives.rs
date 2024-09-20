use secp256k1::{Keypair, SecretKey as Secp256k1SecretKey, XOnlyPublicKey};

use crate::{BlockchainLocation, EdgeLabel, LocalInput};

pub type PublicKey = XOnlyPublicKey;
pub type SecretKey = Secp256k1SecretKey;

pub fn hash(_data: &[u8]) -> [u8; 32] {
    unimplemented!()
}

// A binding and hiding commitment scheme
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Commitment([u8; 32]);

impl Commitment {
    pub fn commit(_msg: &[u8; 32], _rand: &[u8; 32]) -> Self {
        unimplemented!()
    }
}

// Non-interactive Schnorr Signature Half-Aggregation with Commitments
#[derive(Debug, PartialEq, Clone)]
pub struct Signature(pub Vec<u8>);
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct SigCommitment();

impl Signature {
    pub fn keygen_pub(sk: &SecretKey) -> PublicKey {
        let secp = secp256k1::Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, sk);
        XOnlyPublicKey::from_keypair(&keypair).0
    }
    pub fn agg_verify(_sig: &Signature, _pm_aggd: Vec<(PublicKey, secp256k1::Message)>) -> bool {
        unimplemented!()
    }
    pub fn commit_retrieve(_sig: &Signature, _i: usize) -> SigCommitment {
        unimplemented!()
    }
    pub fn commit_verify(_comm: SigCommitment, _msg: &[u8; 32], _pk: &PublicKey) -> bool {
        unimplemented!()
    }
}

// The accumulator represents a set and supports insertion, non-membership
// proofs and is "Strong" (i.e., insertions are verifiable). The accumulator
// satisfies the A-SEC security notion.
//
// The type of elements inserted into the accumulator allows for an
// optimization. Namely the elements are coin.BlockchainLocation, whose
// lexicographic order matches the order in which they were created. Hence, if
// it becomes very unlikely that the manager receives coins older than time T,
// they can forget the data required to prove membership for coins older than T.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct AccValue();
pub struct AccM();
impl AccM {
    pub fn new() -> Self {
        unimplemented!()
    }
    pub fn value(_state: &AccM) -> AccValue {
        unimplemented!()
    }
    pub fn prove_non_membership_and_insert(
        _state: &AccM,
        _elements: Vec<[u8; 8]>,
    ) -> (AccM, Vec<u8>) {
        unimplemented!()
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct AccV();
impl AccV {
    pub fn new() -> AccValue {
        unimplemented!()
    }
    pub fn verify_non_membership_and_insert(
        _v: &AccValue,
        _v_: &AccValue,
        _element: Vec<[u8; 8]>,
        _proof: &[u8],
    ) -> bool {
        unimplemented!()
    }
}

// The ToS-Accumulator represents a tuple of sets.
type ToSAccSetElement = (PublicKey, SigCommitment, BlockchainLocation, Commitment);
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct ToSAccValue();
pub struct ToSAccM();

impl ToSAccM {
    pub fn new() -> Self {
        unimplemented!()
    }
    pub fn value(_state: &ToSAccM) -> ToSAccValue {
        unimplemented!()
    }
    // Append the set to the tuple of sets represented by the accumulator
    pub fn append_set(
        _state: &ToSAccM,
        _set: Vec<(PublicKey, SigCommitment, BlockchainLocation, Commitment)>,
    ) -> Self {
        unimplemented!()
    }
    // Remove the last appended set
    pub fn remove_set(_state: &ToSAccM) -> Self {
        unimplemented!()
    }

    pub fn prove_union_membership(_state: &AccM, _element: ToSAccSetElement) -> Vec<u8> {
        unimplemented!()
    }
    // Prove that the tuples represented by accumulators _state are all
    // prefixes of the tuple represented by _state_
    pub fn prove_is_prefix(_state: &[AccM], _state_: &AccM) -> Vec<u8> {
        unimplemented!()
    }

    // Prove that the tuple represented by accumulator _state and the tuple
    // represented by _state_ have distinct elements
    pub fn prove_distinct_element(_state: &AccM, _state_: &AccM) -> Vec<u8> {
        unimplemented!()
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct ToSAccV(());

impl ToSAccV {
    pub fn new() -> ToSAccValue {
        unimplemented!()
    }
    pub fn verify_union_membership(
        _v: &ToSAccValue,
        _element: ToSAccSetElement,
        _proof: &[u8],
    ) -> bool {
        unimplemented!()
    }
    // Verify that the tuples represented by accumulators _v are all prefixes
    // of the tuple represented by _v_
    pub fn verify_is_prefix(_v: &[ToSAccValue], _v_: &ToSAccValue, _proof: &[u8]) -> bool {
        unimplemented!()
    }

    // Verify that the tuple represented by accumulator _v and the tuple
    // represented by _v_ have distinct elements
    pub fn verify_distinct_element(_v: &ToSAccValue, _v_: &ToSAccValue, _proof: &[u8]) -> bool {
        unimplemented!()
    }
}

pub struct PCD(());
pub struct PCDProvKey(());
pub struct PCDVerKey(());

impl PCD {
    pub fn keygen() -> (PCDProvKey, PCDVerKey) {
        unimplemented!()
    }
    pub fn prove(
        _prk: &PCDProvKey,
        _z: EdgeLabel,
        _w_loc: LocalInput,
        _z_in: &[EdgeLabel],
        _proofs_in: &[u8],
    ) -> Vec<u8> {
        unimplemented!()
    }
    pub fn verify(_vk: &PCDVerKey, _z: EdgeLabel, _proof: &[u8]) -> bool {
        unimplemented!()
    }
}
