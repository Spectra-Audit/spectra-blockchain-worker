#!/usr/bin/env python3
"""Generate admin wallet credentials for Railway deployment.

Run this locally and copy the output to Railway environment variables.
"""
from eth_account import Account

# Enable Mnemonic features
Account.enable_unaudited_hdwallet_features()

print("=" * 60)
print("Spectra Blockchain Worker - Admin Wallet Generator")
print("=" * 60)
print()

# Create a new account
account = Account.create()
private_key = account.key.hex()
address = account.address

print("✅ Admin wallet generated successfully!")
print()
print("IMPORTANT: Add these to your Railway blockchain worker service:")
print()
print("Environment Variable → Value")
print("-" * 40)
print(f"ADMIN_WALLET_ADDRESS → {address}")
print(f"ADMIN_WALLET_PRIVATE_KEY → {private_key}")
print()
print("=" * 60)
print("NEXT STEPS:")
print("=" * 60)
print(f"1. Copy the wallet address: {address}")
print(f"2. Add it to your backend's ADMIN_WALLETS environment variable")
print(f"   Example: ADMIN_WALLETS = {address},0xYOUR_OTHER_WALLET")
print()
print("3. Add BOTH variables above to Railway blockchain worker:")
print("   - Go to Railway → blockchain-worker service → Variables")
print("   - Add ADMIN_WALLET_ADDRESS")
print("   - Add ADMIN_WALLET_PRIVATE_KEY (mark as secret/locked)")
print()
print("⚠️  NEVER share the private key! Keep it secure!")
print("=" * 60)
