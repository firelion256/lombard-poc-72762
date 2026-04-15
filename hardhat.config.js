require("@nomicfoundation/hardhat-toolbox");

module.exports = {
  solidity: "0.8.24",
  networks: {
    hardhat: {
      forking: {
        url: "https://eth-mainnet.g.alchemy.com/v2/ALCHEMY-KEY",
        blockNumber: 22232699,
      },
      chainId: 1,
    },
  },
};
