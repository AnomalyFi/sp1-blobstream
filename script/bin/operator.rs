use alloy::{sol, sol_types::SolValue};
use anyhow::Result;
use blobstream_script::util::TendermintRPCClient;
use blobstream_script::TendermintProver;
use log::{error, info};
use nodekit_seq_sdk::client::jsonrpc_client;
use primitives::get_header_update_verdict;
use serde::{Deserialize, Serialize};
use sp1_recursion_gnark_ffi::PlonkBn254Proof;
use sp1_sdk::{ProverClient, SP1PlonkBn254Proof, SP1ProvingKey, SP1Stdin, SP1VerifyingKey};

use std::{env, fs::File, io::Write};

use tendermint_light_client_verifier::Verdict;

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

#[allow(dead_code)]
struct SP1BlobstreamOperator {
    client: ProverClient,
    pk: SP1ProvingKey,
    rpc_client: jsonrpc_client::JSONRPCClient,
    address: String,
}

#[derive(Serialize, Deserialize)]
struct HelperForJsonFileOutput {
    #[serde(rename = "proof")]
    proof: PlonkBn254Proof,
    #[serde(rename = "verifyingKey")]
    verification_key: SP1VerifyingKey,
}

sol! {
    struct CommitHeaderRangeInput{
        bytes proof;
        bytes publicValues;
    }
}

impl SP1BlobstreamOperator {
    pub async fn new() -> Self {
        dotenv::dotenv().ok();

        let client = ProverClient::new();
        let (pk, _) = client.setup(ELF);

        let rpc_client = jsonrpc_client::JSONRPCClient::new(
            env::var("RPC_URL").unwrap().as_str(),
            env::var("NETWORK_ID").unwrap().parse::<u32>().unwrap(),
            env::var("CHAIN_ID").unwrap(),
        )
        .unwrap();

        let address = env::var("ADDRESS").expect("ADDRESS not set");
        Self {
            client,
            pk,
            rpc_client,
            address,
        }
    }

    async fn request_header_range(
        &self,
        trusted_block: u64,
        target_block: u64,
    ) -> Result<SP1PlonkBn254Proof> {
        let prover = TendermintProver::new();
        let mut stdin = SP1Stdin::new();

        let inputs = prover
            .fetch_input_for_blobstream_proof(trusted_block, target_block)
            .await;

        // Simulate the step from the trusted block to the target block.
        let verdict =
            get_header_update_verdict(&inputs.trusted_light_block, &inputs.target_light_block);
        assert_eq!(verdict, Verdict::Success);

        let encoded_proof_inputs = serde_cbor::to_vec(&inputs)?;
        stdin.write_vec(encoded_proof_inputs.clone());
        let proof = self.client.prove_plonk(&self.pk, stdin).unwrap();
        let helper_output = HelperForJsonFileOutput {
            proof: proof.proof.clone(),
            verification_key: self.pk.vk.clone(),
        };
        let json_output = serde_json::to_string(&helper_output).unwrap();
        let file_name = format!("proof_{}_{}.json", trusted_block, target_block);
        // Create a file and write the data
        let mut file = File::create(file_name).expect("Unable to create file");
        file.write_all(json_output.as_bytes())
            .expect("Unable to write data");
        Ok(proof)
    }

    /// Relay a header range proof to the SP1 Blobstream contract.
    async fn relay_header_range(&self, proof: SP1PlonkBn254Proof) -> Result<()> {
        let public_values_bytes = proof.public_values.to_vec();
        // blobstream wasm smart contract deployed on SEQ takes CommitHeaderRangeInput as input.
        let input = CommitHeaderRangeInput {
            // raw proof is used to verify the plonk proof in gnark.
            // solidity verifier uses encoded proof, packed by first 4 bytes with sp1 version identefier.
            proof: proof.proof.raw_proof.into(),
            // public value bytes are same as the public inputs accepted/used during proof generation.
            publicValues: public_values_bytes.into(),
        };
        let tx_reply = self
            .rpc_client
            .submit_transact_tx(
                String::from("commit_header_range"),
                self.address.clone(),
                input.abi_encode(),
            )
            .unwrap();

        info!("Transaction ID: {:?}", tx_reply.tx_id);

        Ok(())
    }

    async fn run(
        &mut self,
        loop_delay_mins: u64,
        block_interval: u64,
        data_commitment_max: u64,
    ) -> Result<()> {
        info!("Starting SP1 Blobstream operator");
        let mut fetcher = TendermintRPCClient::default();

        let storage_slot = env::var("STORAGE_SLOT_LATEST_BLOCK")
            .unwrap()
            .parse::<u64>()
            .expect("STORAGE_SLOT_LATEST_BLOCK not set");
        loop {
            // Get the latest block from the contract.
            let slot_data = self
                .rpc_client
                .get_storage_slot_data(self.address.clone(), storage_slot.to_be_bytes().to_vec())
                .unwrap();
            let cb_data: [u8; 8] = slot_data.data[0..8].try_into().unwrap();
            let current_block = u64::from_be_bytes(cb_data);
            // Get the head of the chain.
            let latest_tendermint_block_nb = fetcher.get_latest_block_height().await;

            // Subtract 1 block to ensure the block is stable.
            let latest_stable_tendermint_block = latest_tendermint_block_nb - 1;

            // block_to_request is the closest interval of block_interval less than min(latest_stable_tendermint_block, data_commitment_max + current_block)
            let max_block = std::cmp::min(
                latest_stable_tendermint_block,
                data_commitment_max + current_block,
            );
            let block_to_request = max_block - (max_block % block_interval);

            // If block_to_request is greater than the current block in the contract, attempt to request.
            if block_to_request > current_block {
                // The next block the operator should request.
                let max_end_block = block_to_request;

                let target_block = fetcher
                    .find_block_to_request(current_block, max_end_block)
                    .await;

                info!("Current block: {}", current_block);
                info!("Attempting to step to block {}", target_block);

                // Request a header range if the target block is not the next block.
                match self.request_header_range(current_block, target_block).await {
                    Ok(proof) => {
                        self.relay_header_range(proof).await?;
                    }
                    Err(e) => {
                        error!("Header range request failed: {}", e);
                        continue;
                    }
                };
            } else {
                info!("Next block to request is {} which is > the head of the Tendermint chain which is {}. Sleeping.", block_to_request + block_interval, latest_stable_tendermint_block);
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(60 * loop_delay_mins)).await;
        }
    }
}

#[tokio::main]
async fn main() {
    env::set_var("RUST_LOG", "info");
    dotenv::dotenv().ok();
    env_logger::init();

    let loop_delay_mins_env = env::var("LOOP_DELAY_MINS");
    let mut loop_delay_mins = 5;
    if loop_delay_mins_env.is_ok() {
        loop_delay_mins = loop_delay_mins_env
            .unwrap()
            .parse::<u64>()
            .expect("invalid LOOP_DELAY_MINS");
    }

    let update_delay_blocks_env = env::var("UPDATE_DELAY_BLOCKS");
    let mut update_delay_blocks = 300;
    if update_delay_blocks_env.is_ok() {
        update_delay_blocks = update_delay_blocks_env
            .unwrap()
            .parse::<u64>()
            .expect("invalid UPDATE_DELAY_BLOCKS");
    }

    let data_commitment_max_env = env::var("DATA_COMMITMENT_MAX");
    // Note: This default value reflects the max data commitment size that can be rquested from the
    // Celestia node.
    let mut data_commitment_max = 1000;
    if data_commitment_max_env.is_ok() {
        data_commitment_max = data_commitment_max_env
            .unwrap()
            .parse::<u64>()
            .expect("invalid DATA_COMMITMENT_MAX");
    }

    let mut operator = SP1BlobstreamOperator::new().await;
    loop {
        if let Err(e) = operator
            .run(loop_delay_mins, update_delay_blocks, data_commitment_max)
            .await
        {
            error!("Error running operator: {}", e);
        }
    }
}
