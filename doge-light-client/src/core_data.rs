/*
Copyright (C) 2025 Zero Knowledge Labs Limited, QED Protocol

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Additional terms under GNU AGPL version 3 section 7:

As permitted by section 7(b) of the GNU Affero General Public License, 
you must retain the following attribution notice in all copies or 
substantial portions of the software:

"This software was created by QED (https://qedprotocol.com)
with contributions from Carter Feldman (https://x.com/cmpeq)."
*/

#[cfg(feature = "borsh")]
use borsh::{BorshSerialize, BorshDeserialize};
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};


use zerocopy_derive::{FromBytes, Immutable, IntoBytes};

use crate::{
    constants::{DogeNetworkConfig, MERGED_MINING_HEADER, VERSION_AUXPOW}, doge::transaction::BTCTransaction, error::{DogeBridgeError, QDogeResult}, hash::{
        merkle, scrypt_doge::scrypt_1024_1_1_256, sha256::QBTCHash256Hasher, traits::{BytesHasher, MerkleHasher}
    }
};
use bytes::{Buf, BufMut};

pub type QHash256 = [u8; 32];
pub type QHash160 = [u8; 20];
fn find_in_array(data: &[u8], search_sub_array: &[u8]) -> Option<usize> {
    // If the sub-array is empty, return None
    if search_sub_array.is_empty() || data.len() < search_sub_array.len() {
        return None;
    }

    // Iterate over the `data` array
    for i in 0..=data.len().saturating_sub(search_sub_array.len()) {
        // Check if the sub-array matches at the current position
        if data[i..i + search_sub_array.len()] == *search_sub_array {
            return Some(i); // Return the starting index
        }
    }

    None
}
// Return


#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[derive(Copy, Clone, Debug, Default, PartialEq, PartialOrd, Eq, Ord, FromBytes, IntoBytes, Immutable)]
pub struct QStandardBlockHeader {
    pub version: u32,
    pub previous_block_hash: QHash256,
    pub merkle_root: QHash256,
    pub timestamp: u32,
    pub bits: u32,
    pub nonce: u32,
}


impl QStandardBlockHeader {
    pub fn to_bytes_fixed(&self) -> [u8; 80] {
        let  mut bytes = [0u8; 80];
        let mut buf = &mut bytes[..];
        buf.put_u32_le(self.version);
        buf.put_slice(&self.previous_block_hash);
        buf.put_slice(&self.merkle_root);
        buf.put_u32_le(self.timestamp);
        buf.put_u32_le(self.bits);
        buf.put_u32_le(self.nonce);

        bytes
    }
    pub fn from_bytes_fixed(data: &[u8; 80]) -> Self {
        let mut buf = data.as_ref();
        let version = buf.get_u32_le();
        let mut previous_block_hash = [0u8; 32];
        let mut merkle_root = [0u8; 32];
        buf.copy_to_slice(&mut previous_block_hash);
        buf.copy_to_slice(&mut merkle_root);
        let timestamp = buf.get_u32_le();
        let bits = buf.get_u32_le();
        let nonce = buf.get_u32_le();
        Self {
            version,
            previous_block_hash,
            merkle_root,
            timestamp,
            bits,
            nonce,
        }
    }

    pub fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() < 80 {
            anyhow::bail!(
                "error deserializing QStandardBlockHeader: expected at least 80 bytes, got {}",
                data.len()
            );
        }
        let mut buf = data;
        let version = buf.get_u32_le();
        let mut previous_block_hash = [0u8; 32];
        let mut merkle_root = [0u8; 32];
        buf.copy_to_slice(&mut previous_block_hash);
        buf.copy_to_slice(&mut merkle_root);
        let timestamp = buf.get_u32_le();
        let bits = buf.get_u32_le();
        let nonce = buf.get_u32_le();
        Ok(Self {
            version,
            previous_block_hash,
            merkle_root,
            timestamp,
            bits,
            nonce,
        })
    }
    pub fn get_hash(&self) -> QHash256 {
        QBTCHash256Hasher::hash_bytes(&self.to_bytes_fixed())
    }
    pub fn get_pow_hash(&self) -> QHash256 {
        scrypt_1024_1_1_256(&self.to_bytes_fixed())
    }
    pub fn get_chain_id(&self) -> u32 {
        self.version >> 16
    }
    pub fn is_aux_pow(&self) -> bool {
        (self.version & VERSION_AUXPOW) != 0
    }
}


#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct QMerkleBranch {
    pub hashes: Vec<QHash256>,
    pub side_mask: u32,
}

impl QMerkleBranch {
    pub fn get_root<H: MerkleHasher<QHash256>>(&self, value: QHash256) -> QHash256 {
        let mut cur = value;
        let mut cur_index = self.side_mask;
        for h in self.hashes.iter() {
            cur = H::two_to_one_swap((cur_index & 1) == 1, &cur, h);
            cur_index >>= 1;
        }
        cur
    }
}


#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct QAuxPow {
    pub coinbase_transaction: BTCTransaction,
    pub block_hash: QHash256,
    pub coinbase_branch: QMerkleBranch,
    pub blockchain_branch: QMerkleBranch,
    pub parent_block: QStandardBlockHeader,
}

pub fn get_expected_index(n_nonce: u32, n_chain_id: i32, h: u32) -> u32 {
    // Choose a pseudo-random slot in the chain merkle tree
    // but have it be fixed for a size/nonce/chain combination.
    //
    // This prevents the same work from being used twice for the
    // same chain while reducing the chance that two chains clash
    // for the same slot.

    /* This computation can overflow the uint32 used.  This is not an issue,
    though, since we take the mod against a power-of-two in the end anyway.
    This also ensures that the computation is, actually, consistent
    even if done in 64 bits as it was in the past on some systems.

    Note that h is always <= 30 (enforced by the maximum allowed chain
    merkle branch length), so that 32 bits are enough for the computation.  */

    let mut r = n_nonce;
    r = r.wrapping_mul(1103515245).wrapping_add(12345).wrapping_add(n_chain_id as u32);
    r = r.wrapping_mul(1103515245).wrapping_add(12345);

    return r % (1 << h);
}

impl QAuxPow {
    pub fn check<NC: DogeNetworkConfig>(&self, hash_aux_block: QHash256, chain_id: u32) -> bool {
        if self.coinbase_branch.side_mask == 0
            && self.blockchain_branch.hashes.len() <= 30
            && (!NC::NETWORK_PARAMS.strict_chain_id
                || self.parent_block.get_chain_id() == chain_id)
        {
            let n_root_hash = self
                .blockchain_branch
                .get_root::<QBTCHash256Hasher>(hash_aux_block);
            let mut vch_root_hash = n_root_hash.clone();

            vch_root_hash.reverse();

            let coinbase_tx_hash = self.coinbase_transaction.get_hash();

            let coinbase_root = self
                .coinbase_branch
                .get_root::<QBTCHash256Hasher>(coinbase_tx_hash);
            if coinbase_root == self.parent_block.merkle_root {
                if self.coinbase_transaction.inputs.len() > 0 {
                    let script = self.coinbase_transaction.inputs[0].script.clone();
                    let pc = find_in_array(&script, &vch_root_hash);
                    let pc_head = find_in_array(&script, &MERGED_MINING_HEADER);

                    if pc.is_some() {
                        let mut pc = pc.unwrap();
                        if pc_head.is_some() {
                            let pc_head = pc_head.unwrap();
                            if find_in_array(&script[pc_head..], &MERGED_MINING_HEADER).is_some() {
                                return false;
                            } else if pc_head + MERGED_MINING_HEADER.len() != pc {
                                return false;
                            }
                        } else {
                            // For backward compatibility.
                            // Enforce only one chain merkle root by checking that it starts early in the coinbase.
                            // 8-12 bytes are enough to encode extraNonce and nBits.
                            if pc > 20 {
                                return false;
                            }
                        }
                        pc += 32;
                        if script.len() - pc < 8 {
                            return false;
                        }
                        let n_size = u32::from_le_bytes(script[pc..(pc + 4)].try_into().unwrap());
                        let merkle_height = self.blockchain_branch.hashes.len();
                        if n_size != (1u32 << merkle_height) {
                            return false;
                        }
                        let n_nonce =
                            u32::from_le_bytes(script[(pc + 4)..(pc + 8)].try_into().unwrap());

                        if self.blockchain_branch.side_mask
                            != get_expected_index(n_nonce, chain_id as i32, merkle_height as u32)
                        {
                            return false;
                        }

                        return true;
                    }
                }
            }
        }
        false
    }
    pub fn check_err<NC: DogeNetworkConfig>(&self, hash_aux_block: QHash256, chain_id: u32) -> QDogeResult<()> {
        if self.coinbase_branch.side_mask != 0 {
            return Err(DogeBridgeError::AuxPowCoinBaseBranchSideMaskNonZero);
        } else if self.blockchain_branch.hashes.len() > 30 {
            return Err(DogeBridgeError::AuxPowChainMerkleBranchTooLong);
        } else if NC::NETWORK_PARAMS.strict_chain_id
            && self.parent_block.get_chain_id() == chain_id
        {
            return Err(DogeBridgeError::AuxPowParentHasOurChainId);
        }

        let n_root_hash = self
            .blockchain_branch
            .get_root::<QBTCHash256Hasher>(hash_aux_block);
        let mut vch_root_hash = n_root_hash.clone();

        vch_root_hash.reverse();

        let coinbase_tx_hash = self.coinbase_transaction.get_hash();

        let coinbase_root = self
            .coinbase_branch
            .get_root::<QBTCHash256Hasher>(coinbase_tx_hash);

        if coinbase_root != self.parent_block.merkle_root {
            return Err(DogeBridgeError::IncorrectAuxPowMerkleRoot);
        }
        if self.coinbase_transaction.inputs.len() == 0 {
            return Err(DogeBridgeError::AuxPowCoinbaseNoInputs);
        }
        let script = self.coinbase_transaction.inputs[0].script.clone();
        let pc = find_in_array(&script, &vch_root_hash);
        if pc.is_none() {
            return Err(DogeBridgeError::AuxPowCoinbaseMissingChainMerkleRoot);
        }
        let mut pc = pc.unwrap();
        let pc_head = find_in_array(&script, &MERGED_MINING_HEADER);

        if pc_head.is_some() {
            let pc_head = pc_head.unwrap();
            if find_in_array(&script[(pc_head+MERGED_MINING_HEADER.len())..], &MERGED_MINING_HEADER).is_some() {
                return Err(DogeBridgeError::MergedMiningHeaderFoundTwiceInCoinbase);
            } else if pc_head + MERGED_MINING_HEADER.len() != pc {
                return Err(DogeBridgeError::MergedMiningHeaderNotFoundAtCoinbaseScriptStart);
            }
        } else {
            // For backward compatibility.
            // Enforce only one chain merkle root by checking that it starts early in the coinbase.
            // 8-12 bytes are enough to encode extraNonce and nBits.
            if pc > 20 {
                return Err(DogeBridgeError::AuxPowChainMerkleRootTooLateInCoinbaseInputScript);
            }
        }
        pc += 32;
        if script.len() - pc < 8 {
            return Err(DogeBridgeError::AuxPowCoinbaseTransactionInputScriptTooShort);
        }
        let n_size = u32::from_le_bytes(script[pc..(pc + 4)].try_into().unwrap());
        let merkle_height = self.blockchain_branch.hashes.len();
        if n_size != (1u32 << merkle_height) {
            return Err(DogeBridgeError::AuxPowCoinbaseScriptInvalidNSize);
        }
        let n_nonce = u32::from_le_bytes(script[(pc + 4)..(pc + 8)].try_into().unwrap());

        if self.blockchain_branch.side_mask
            != get_expected_index(n_nonce, chain_id as i32, merkle_height as u32)
        {
            return Err(DogeBridgeError::AuxPowCoinbaseScriptInvalidSideMask);
        }
        Ok(())
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[derive(Clone, Debug, PartialEq, Default, Eq, Ord, PartialOrd)]
pub struct QDogeBlockHeader {
    pub header: QStandardBlockHeader,
    pub aux_pow: Option<QAuxPow>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct QDogeBlock {
    pub header: QStandardBlockHeader,
    pub aux_pow: Option<QAuxPow>,
    pub transactions: Vec<BTCTransaction>,
}

impl QDogeBlock {
    pub fn to_qdoge_block_header(&self) -> QDogeBlockHeader {
        QDogeBlockHeader {
            header: self.header.clone(),
            aux_pow: self.aux_pow.clone(),
        }
    }
}
