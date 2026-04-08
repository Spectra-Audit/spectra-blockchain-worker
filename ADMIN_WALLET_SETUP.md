# Blockchain Worker Admin Wallet Setup

## ✅ Completed Steps

1. **Generated Admin Wallet**
   - Wallet address: `0x808B25bC600f9B963A667a551fab4C039B834157`
   - Private key: `74f6fe51e79583f1caa15dd19beba61a3c60c89f6237afe7371b26bcc681b0a3`

2. **Updated Railway.toml**
   - Added `ADMIN_ACCESS_TOKEN` = `spectra-admin-token-2026`
   - Added `ADMIN_WALLET_ADDRESS` = `0x808B25bC600f9B963A667a551fab4C039B834157`
   - Added `ADMIN_WALLET_PRIVATE_KEY` (marked as SECRET)

3. **Updated .env File**
   - Added `ADMIN_ACCESS_TOKEN` = `spectra-admin-token-2026`

## 📋 Next Steps (User Action Required)

### Step 1: Add Wallet to Backend Configuration

**Backend Location:** `SpectraBackend/spectra-backend/.env` or Railway dashboard

Add the admin wallet address to the backend's `ADMIN_WALLETS` environment variable:

```bash
ADMIN_WALLETS=0x808B25bC600f9B963A667a551fab4C039B834157,0xYOUR_OTHER_ADMIN_WALLETS_IF_NEEDED
```

**Why this is needed:** The backend needs to recognize this wallet as an admin for SIWE authentication verification.

### Step 2: Redeploy Blockchain Worker

**Method 1: Via Railway Dashboard**
1. Go to Railway.app → select blockchain-worker service
2. Go to "Variables" tab
3. Add these environment variables:
   - `ADMIN_ACCESS_TOKEN` = `spectra-admin-token-2026`
   - `ADMIN_WALLET_ADDRESS` = `0x808B25bC600f9B963A667a551fab4C039B834157`
   - `ADMIN_WALLET_PRIVATE_KEY` = `74f6fe51e79583f1caa15dd19beba61a3c60c89f6237afe7371b26bcc681b0a3`
4. Mark `ADMIN_WALLET_PRIVATE_KEY` as a **Secret** (click lock icon)
5. Click "Redeploy" button

**Method 2: Via Railway CLI**
```bash
railway up
```

## 🔐 Security Notes

- ✅ The private key is already set as a SECRET in Railway.toml
- ✅ Never commit the private key to version control
- ✅ Keep the private key secure and never share it
- ✅ If you need to regenerate the wallet, run `python3 generate_admin_wallet.py`

## ✅ Verification

After redeployment, check the blockchain worker logs for successful SIWE authentication:

```bash
# Expected log message:
# [info] SIWE handshake successful - tokens cached for future requests
```

The executive summaries should then be successfully stored in the database and appear on the frontend detailed analysis tab.
