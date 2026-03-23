#!/usr/bin/env python3
"""
Manual payment verification script.

Use this to verify a payment transaction when the blockchain worker
has skipped past the block containing the payment event.

Usage:
    python verify_payment_manual.py <transaction_hash>
"""
from __future__ import annotations

import os
import sys
import json
from decimal import Decimal

# Setup path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from web3 import Web3
except ImportError:
    print("Error: web3 required")
    print("Install with: pip install web3")
    sys.exit(1)


def main():
    if len(sys.argv) < 2:
        print("Usage: python verify_payment_manual.py <transaction_hash>")
        print("\nExample:")
        print('  python verify_payment_manual.py 0x346da8a60985e67cd5b9c8fee960ff7f63507b5a3a9ca14613b4f4921e11aae1')
        sys.exit(1)

    tx_hash = sys.argv[1]

    # Ensure 0x prefix
    if not tx_hash.startswith("0x"):
        tx_hash = "0x" + tx_hash

    print(f"Verifying payment transaction: {tx_hash}")

    # Setup Web3
    rpc_url = os.environ.get("RPC_HTTP_URL", "https://eth.llamarpc.com")
    print(f"Connecting to RPC: {rpc_url}")

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        print("Error: Failed to connect to RPC")
        sys.exit(1)

    print("Connected successfully")

    # Get transaction receipt
    try:
        receipt = w3.eth.get_transaction_receipt(tx_hash)
    except Exception as e:
        print(f"Error: Failed to get transaction receipt: {e}")
        sys.exit(1)

    print(f"\nTransaction Details:")
    print(f"  Block: {receipt.blockNumber}")
    print(f"  From: {receipt['from']}")
    print(f"  To: {receipt['to']}")
    print(f"  Status: {'Success' if receipt.status == 1 else 'Failed'}")

    if receipt.status != 1:
        print("Error: Transaction failed")
        sys.exit(1)

    # Parse the Paid event logs
    # Paid(address indexed payer, address indexed creator, bytes32 indexed projectId,
    #      uint256 amountPaidFees, uint8 numberOfContracts, uint256 featuredBid, uint64 roundId)
    # Topic0: event signature
    # Topic1: payer
    # Topic2: creator
    # Topic3: projectId
    # Data: amountPaidFees (32) + numberOfContracts (1) + featuredBid (32) + roundId (8)

    PAID_TOPIC = w3.keccak(text="Paid(address,address,bytes32,uint256,uint8,uint256,uint64)").hex()

    for log in receipt.logs:
        if log.topics and log.topics[0].hex() == PAID_TOPIC:
            print(f"\nFound Paid event:")

            # Extract indexed parameters from topics
            payer = w3.to_checksum_address(log.topics[1][-20:])
            creator = w3.to_checksum_address(log.topics[2][-20:])
            project_id_bytes = log.topics[3]
            project_id = "0x" + project_id_bytes.hex()

            # Decode data
            data = w3.codec.decode(["uint256", "uint8", "uint256", "uint64"], log.data)
            amount_paid_fees = data[0]
            number_of_contracts = data[1]
            featured_bid = data[2]
            round_id = data[3]

            # Convert amount from wei to VERITAS
            amount_veritas = amount_paid_fees / 1e18

            print(f"  Payer: {payer}")
            print(f"  Creator: {creator}")
            print(f"  Project ID: {project_id}")
            print(f"  Amount Paid: {amount_veritas} VERITAS ({amount_paid_fees} wei)")
            print(f"  Number of Contracts: {number_of_contracts}")
            print(f"  Featured Bid: {featured_bid}")
            print(f"  Round ID: {round_id}")

            # Prepare payload for admin endpoint
            payload = {
                "creator_address": creator,
                "amount_paid": str(int(amount_veritas)),
                "transaction_hash": tx_hash,
                "block_number": receipt.blockNumber,
                "round_id": round_id,
            }

            print(f"\nPayload for admin endpoint:")
            print(json.dumps(payload, indent=2))

            # Get API base URL
            api_base_url = os.environ.get("API_BASE_URL", "http://localhost:8000/v1")
            if not api_base_url.endswith("/v1"):
                api_base_url = api_base_url.rstrip("/") + "/v1"

            print(f"\nTo verify this payment, call:")
            print(f"  POST {api_base_url}/admin/verify-payment-and-create")
            print(f"  Headers:")
            print(f"    Content-Type: application/json")
            print(f"    X-Admin-API-Key: <your admin key>")
            print(f"  Body:")
            print(f"    {json.dumps(payload)}")

            # Optionally make the request
            if "--execute" in sys.argv:
                admin_api_key = os.environ.get("BLOCKCHAIN_WORKER_API_KEY")
                if not admin_api_key:
                    print("\nError: BLOCKCHAIN_WORKER_API_KEY not set")
                    print("Set it with: export BLOCKCHAIN_WORKER_API_KEY=your_key")
                    sys.exit(1)

                import requests

                url = f"{api_base_url}/admin/verify-payment-and-create"
                headers = {
                    "Content-Type": "application/json",
                    "X-Admin-API-Key": admin_api_key,
                }

                print(f"\nCalling admin endpoint...")
                response = requests.post(url, json=payload, headers=headers, timeout=30)

                print(f"Response status: {response.status_code}")
                print(f"Response body: {response.text}")

                if response.status_code == 200:
                    print("\n✅ Payment verified and project created successfully!")
                else:
                    print(f"\n❌ Error: {response.status_code}")

            return

    print("\nError: No Paid event found in transaction logs")
    sys.exit(1)


if __name__ == "__main__":
    main()
