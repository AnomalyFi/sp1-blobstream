use alloy::{
    network::{Ethereum, EthereumWallet},
    primitives::Address,
    providers::{
        fillers::{ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller},
        Identity, ProviderBuilder, RootProvider,
    },
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolValue,
    transports::http::{Client, Http},
};
use anyhow::Result;
use blobstream_script::util::TendermintRPCClient;
use blobstream_script::TendermintProver;
use log::{error, info};
use nodekit_seq_sdk::client::jsonrpc_client;
use primitives::get_header_update_verdict;
use sp1_sdk::{ProverClient, SP1PlonkBn254Proof, SP1ProvingKey, SP1Stdin};
use std::env;
use std::sync::Arc;

use tendermint_light_client_verifier::Verdict;

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

/// Alias the fill provider for the Ethereum network. Retrieved from the instantiation of the
/// ProviderBuilder. Recommended method for passing around a ProviderBuilder.
type EthereumFillProvider = FillProvider<
    JoinFill<
        JoinFill<JoinFill<JoinFill<Identity, GasFiller>, NonceFiller>, ChainIdFiller>,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider<Http<Client>>,
    Http<Client>,
    Ethereum,
>;

#[allow(dead_code)]
struct SP1BlobstreamOperator {
    client: ProverClient,
    pk: SP1ProvingKey,
    wallet_filler: Arc<EthereumFillProvider>,
    contract_address: Address,
    relayer_address: Address,
    chain_id: u64,
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract SP1Blobstream {
        bool public frozen;
        uint64 public latestBlock;
        uint256 public state_proofNonce;
        mapping(uint64 => bytes32) public blockHeightToHeaderHash;
        mapping(uint256 => bytes32) public state_dataCommitments;
        uint64 public constant DATA_COMMITMENT_MAX = 10000;
        bytes32 public blobstreamProgramVkey;
        address public verifier;

        function commitHeaderRange(bytes calldata proof, bytes calldata publicValues) external;
    }

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
        let chain_id: u64 = env::var("CHAIN_ID")
            .expect("CHAIN_ID not set")
            .parse()
            .unwrap();
        let rpc_url = env::var("RPC_URL")
            .expect("RPC_URL not set")
            .parse()
            .unwrap();

        let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY not set");
        let contract_address = env::var("CONTRACT_ADDRESS")
            .expect("CONTRACT_ADDRESS not set")
            .parse()
            .unwrap();
        let signer: PrivateKeySigner = private_key.parse().expect("Failed to parse private key");
        let relayer_address = signer.address();
        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet)
            .on_http(rpc_url);

        Self {
            client,
            pk,
            wallet_filler: Arc::new(provider),
            chain_id,
            contract_address,
            relayer_address,
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
        stdin.write_vec(encoded_proof_inputs);

        self.client.prove_plonk(&self.pk, stdin)
    }

    /// Relay a header range proof to the SP1 Blobstream contract.
    async fn relay_header_range(&self, proof: SP1PlonkBn254Proof) -> Result<()> {
        let public_values_bytes = proof.public_values.to_vec();
        let client = jsonrpc_client::JSONRPCClient::new(
            env::var("RPC_URL").unwrap().as_str(),
            env::var("NETWORK_ID").unwrap().parse::<u32>().unwrap(),
            env::var("CHAIN_ID").unwrap(),
        )
        .unwrap();
        // blobstream wasm smart contract deployed on SEQ takes CommitHeaderRangeInput as input.
        let input = CommitHeaderRangeInput {
            // raw proof is used to verify the plonk proof in gnark.
            // solidity verifier uses encoded proof, packed by first 4 bytes with sp1 version identefier.
            proof: proof.proof.raw_proof.into(),
            // public value bytes are same as the public inputs accepted/used during proof generation.
            publicValues: public_values_bytes.into(),
        };
        let tx_reply = client
            .submit_transact_tx(
                env::var("CHAIN_ID").unwrap(),
                env::var("NETWORK_ID").unwrap().parse::<u32>().unwrap(),
                String::from("commit_header_range"),
                env::var("CONTRACT_ADDRESS").unwrap(),
                input.abi_encode(),
            )
            .unwrap();

        // @todo check the transaction status and act accordingly.
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
        let rpc_url = env::var("RPC_URL").expect("RPC_URL not set");
        let network_id = env::var("NETWORK_ID")
            .unwrap()
            .parse::<u32>()
            .expect("NETWORK_ID not set");
        let chain_id = env::var("CHAIN_ID").expect("CHAIN_ID not set");
        let address = env::var("ADDRESS").expect("ADDRESS not set");
        let storage_slot = env::var("STORAGE_SLOT")
            .unwrap()
            .parse::<u64>()
            .expect("STORAGE_SLOT not set");
        loop {
            let client =
                jsonrpc_client::JSONRPCClient::new(rpc_url.as_str(), network_id, chain_id.clone())
                    .unwrap();
            // Get the latest block from the contract.
            let slot_data = client
                .get_storage_slot_data(address.clone(), storage_slot)
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
