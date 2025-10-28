# spectra-blockchain-worker
The blockchain worker is an external piece to the spectra backend which checks and scouts the blockchain. This is because awaiting blockchain transactions is a slow and heavy process. So segragating it allows for more throughput from the backend.

# How It Works:
It scouts the blockchain's events and updates the backend accordingly in a secure manner.
