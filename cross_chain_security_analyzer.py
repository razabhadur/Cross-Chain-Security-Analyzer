
import requests
from web3 import Web3

class CrossChainSecurityAnalyzer:
    def __init__(self, etherscan_api_key, bscscan_api_key, polygonscan_api_key):
        self.etherscan_api_key = etherscan_api_key
        self.bscscan_api_key = bscscan_api_key
        self.polygonscan_api_key = polygonscan_api_key

    # Fetch transactions from Ethereum using Etherscan API
    def fetch_ethereum_transactions(self, wallet_address):
        url = f"https://api.etherscan.io/api?module=account&action=txlist&address={wallet_address}&sort=asc&apikey={self.etherscan_api_key}"
        response = requests.get(url)
        transactions = response.json().get('result', [])
        return transactions
    
    # Fetch transactions from Binance Smart Chain using BscScan API
    def fetch_bsc_transactions(self, wallet_address):
        url = f"https://api.bscscan.com/api?module=account&action=txlist&address={wallet_address}&sort=asc&apikey={self.bscscan_api_key}"
        response = requests.get(url)
        transactions = response.json().get('result', [])
        return transactions
    
    # Fetch transactions from Polygon using Polygonscan API
    def fetch_polygon_transactions(self, wallet_address):
        url = f"https://api.polygonscan.com/api?module=account&action=txlist&address={wallet_address}&sort=asc&apikey={self.polygonscan_api_key}"
        response = requests.get(url)
        transactions = response.json().get('result', [])
        return transactions

    # Analyze known bridges for vulnerabilities
    def analyze_bridge(self, bridge_name):
        known_vulnerabilities = {
            "Binance Bridge": "Replay Attack",
            "Polygon Bridge": "Improper Validation",
        }
        return known_vulnerabilities.get(bridge_name, "No vulnerabilities found")

    # Check for replay attacks by comparing transaction hashes across chains
    def detect_replay_attacks(self, eth_transactions, bsc_transactions, polygon_transactions):
        eth_hashes = {tx['hash'] for tx in eth_transactions}
        bsc_hashes = {tx['hash'] for tx in bsc_transactions}
        polygon_hashes = {tx['hash'] for tx in polygon_transactions}
        
        # Find matching transaction hashes across chains
        replayed_on_bsc = eth_hashes.intersection(bsc_hashes)
        replayed_on_polygon = eth_hashes.intersection(polygon_hashes)
        
        return {
            "Ethereum-BSC Replay": replayed_on_bsc,
            "Ethereum-Polygon Replay": replayed_on_polygon
        }

    # Analyze the transactions to find potential issues
    def analyze_transactions(self, transactions):
        risky_transactions = []
        for tx in transactions:
            if self.is_suspicious_transaction(tx):
                risky_transactions.append(tx)
        return risky_transactions

    # Simple rule-based risk scoring
    def is_suspicious_transaction(self, transaction):
        if transaction['value'] > 100:
            return True
        return False

    # Risk score calculator
    def calculate_risk_score(self, transaction):
        base_risk = 0.2  # Base risk for any transaction
        if self.is_suspicious_transaction(transaction):
            base_risk += 0.5  # Increase risk score for large or suspicious transactions
        return base_risk

    # Fetch and analyze transactions for cross-chain risk
    def analyze_cross_chain_transactions(self, wallet_address):
        eth_tx = self.fetch_ethereum_transactions(wallet_address)
        bsc_tx = self.fetch_bsc_transactions(wallet_address)
        polygon_tx = self.fetch_polygon_transactions(wallet_address)

        print(f"Ethereum Transactions: {eth_tx}")
        print(f"Binance Smart Chain Transactions: {bsc_tx}")
        print(f"Polygon Transactions: {polygon_tx}")

        # Detect replay attacks
        replay_attacks = self.detect_replay_attacks(eth_tx, bsc_tx, polygon_tx)
        print(f"Replay Attacks Detected: {replay_attacks}")

        # Risk analysis
        for chain, txs in {"Ethereum": eth_tx, "BSC": bsc_tx, "Polygon": polygon_tx}.items():
            risky_txs = self.analyze_transactions(txs)
            print(f"Risky Transactions on {chain}: {risky_txs}")
            
            # Calculate risk scores
            for tx in txs:
                risk_score = self.calculate_risk_score(tx)
                print(f"Transaction {tx['hash']} on {tx['chain']} has a risk score of {risk_score}")

# Example usage
def main():
    etherscan_api_key = "YOUR_ETHERSCAN_API_KEY"
    bscscan_api_key = "YOUR_BSCSCAN_API_KEY"
    polygonscan_api_key = "YOUR_POLYGONSCAN_API_KEY"
    
    analyzer = CrossChainSecurityAnalyzer(etherscan_api_key, bscscan_api_key, polygonscan_api_key)
    
    # Analyze known cross-chain bridge
    bridge_vulnerability = analyzer.analyze_bridge("Binance Bridge")
    print(f"Bridge Vulnerability Analysis: {bridge_vulnerability}")
    
    # Fetch and analyze transactions for a wallet address
    wallet_address = "0xYourWalletAddressHere"
    analyzer.analyze_cross_chain_transactions(wallet_address)

if __name__ == "__main__":
    main()
