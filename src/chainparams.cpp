// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2020 The PIVX developers
// Copyright (c) 2019-2020 The Guapcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "chainparamsseeds.h"
#include "consensus/merkle.h"
#include "util.h"
#include "utilstrencodings.h"

#include <boost/assign/list_of.hpp>

#include <assert.h>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
	CMutableTransaction txNew;
	txNew.nVersion = 1;
	txNew.vin.resize(1);
	txNew.vout.resize(1);
	txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
	txNew.vout[0].nValue = genesisReward;
	txNew.vout[0].scriptPubKey = genesisOutputScript;

	CBlock genesis;
	genesis.vtx.push_back(txNew);
	genesis.hashPrevBlock.SetNull();
	genesis.nVersion = nVersion;
	genesis.nTime = nTime;
	genesis.nBits = nBits;
	genesis.nNonce = nNonce;
	genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
	return genesis;
}

/**
* Build the genesis block. Note that the output of the genesis coinbase cannot
* be spent as it did not originally exist in the database.
*
* CBlock(hash=00000ffd590b14, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=e0028e, nTime=1390095618, nBits=1e0ffff0, nNonce=28917698, vtx=1)
*   CTransaction(hash=e0028e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
*     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d01044c5957697265642030392f4a616e2f3230313420546865204772616e64204578706572696d656e7420476f6573204c6976653a204f76657273746f636b2e636f6d204973204e6f7720416363657074696e6720426974636f696e73)
*     CTxOut(nValue=50.00000000, scriptPubKey=0xA9037BAC7050C479B121CF)
*   vMerkleTree: e0028e
*/
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
	const char* pszTimestamp = "Guapcoin is born! - zabtc 22/07/2019";
	const CScript genesisOutputScript = CScript() << ParseHex("04f5a8143f86ad8ac63791fbbdb8e0b91a8da88c8c693a95f6c2c13c063ea790f7960b8025a9047a7bc671d5cfe707a2dd2e13b86182e1064a0eea7bf863636363") << OP_CHECKSIG;
	return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
* Main network
*/
/**
* What makes a good checkpoint block?
* + Is surrounded by blocks with reasonable timestamps
*   (no blocks before with a timestamp after, none after with
*    timestamp before)
* + Contains no strange transactions
*/
static Checkpoints::MapCheckpoints mapCheckpoints =
boost::assign::map_list_of
(0, uint256("0x000002563024b106ca6630ff598e3016fc218f6c5f21366623bce0e75bfc2064"))
(1, uint256("0x0e2fab8d31e8d8634ca0362243de7ca83eac04ba1ced59f1ff99e9a6d644bf2a"))
(3767, uint256("0x1f74d425ad92af620d08705d330e24b9da7b58b8c1c55575b375a9d4f14b1cec"))
(14376, uint256("0xf47349ad64bbcfe2e352bc895beb16da44e80ed1e1d7717619e67b0658166735"))
(35401, uint256("0x3a43fb32b42c6888f729329907a0ec34d8738a9510519c5b23978b5906f56d44"))
(52349, uint256("0x82eeba69db87775a2803925faef46ece52914545362a11cd9c3a387ceb042275"))
(103425, uint256("0x8bab25a3273ac98ef501c2f04257ef0a85eeac0aaf0f07379397e735d59325df"))
(176291, uint256("0x23973a4d350efed956cd680ebe0dde3ed1472ea1486e4a7876d09651bb9a8642"))
(267328, uint256("0x5acfb88f4d06633b2c55a0e0ca1a8f7d1e8537a64e3cc715c41b06d959dcb31b"))
(320745, uint256("0x1c287911ae3816071234696cc11fe379730c9edd40c0f86ef5845004ca362563"))
(355009, uint256("0xa01206f1d04bd976708436637b6e99d2d3f1fc7cfed0c9a9204a9b0f1e1b2c57"))
(367887, uint256("0x5c16c4b81dd0fad34af9b0f144918de8a7d94adfaae2736fdbd21858bdc868d3"))
(387447, uint256("0xa328aa25559f1d7bf1b83a961e984c05da326bd216b1ce30719071b08548d73c"))
(418745, uint256("0x8d0bb1f00b5e66e7b9d4751ff9b54f2a28b6b60eaaabccfaa860eade16a1310d"))
(455009, uint256("0xc50e7a2e7410c8d703a8845f1480af5ca20b8d28e27c63f94706373c9e4131b3"))
(561001, uint256("0xb9a638a632df77a47601450d2391495d1c8f6554871c546db897744660c1f0e3"))
(561003, uint256("0xbc11bdc430210cb691e2439345b9de684456a9118b53e6f38511182a73712717"))
(561004, uint256("0xd8dafe7f56281e1f01a0b22ace43b365411c9dc1d4cf8e7d89086f5d95a5c8e4"))
(561005, uint256("0xa99f9e6fa7da5eb3c62367d2ee896e13cb296e21614be320ccdd2c9fe6cb591e"))
(561017, uint256("0x134abdf34b70271f9517d32c1fc10383c73a7c941cf981ae62f08c350a459d04"))
(563432, uint256("0xb850feaef294481b6ea24178ef0ba91e31f16ba73ea19ab7a89fc8030efa0a77"))
(566102, uint256("0xddf485953d97242dc0c26f480fc4a2e2df2ae3195271bbce08ff76a51141cca8"))
(583265, uint256("0xa69fae992d4fbff77af26fad6905f8600ac60c10c7a7c4efe38c5362ebc75a5f"))
(605106, uint256("0x96b626e2c1a6872ce9d0895625ac742025979780fffd34154c03d0544cb02786"))
(653180, uint256("0xb16c4ce3cc67f0b9e7c3b019e2a3c7a0196ad2f4c3acac6565294dbd67742b96"))
(653458, uint256("0x5fceceecc09ffc6636a34d88b12c797385c5d346f755906b6dec897e8fe4febb"))
(654299, uint256("0x7a466fd270e06a113dddf82ef7db37ab80829f73da48d53449979ee8e95a57e3"))
(655807, uint256("0x8d55ca98f8a1c1c6d52eb990c758690ccc4a6997fd2aa272ebbb980de22b96ea"))
(745263, uint256("0x35652e1d82715103bb3aa8f6860f7fa2eef36e240f0b989e26b49c3d585c3f56"))
(800301, uint256("0xca03809b634910c7a7a19f24e1696d7054da13e50779e4d60a5034fe55f4b705"))
;

static const Checkpoints::CCheckpointData data = {
	&mapCheckpoints,
	1612842465, // * UNIX timestamp of last checkpoint block
	1687105,    // * total number of transactions between genesis and last checkpoint
				//   (the tx=... number in the UpdateTip debug.log lines)
	2000        // * estimated number of transactions per day after checkpoint
};

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
boost::assign::map_list_of
(0, uint256S("0x001"));
static const Checkpoints::CCheckpointData dataTestnet = {
	&mapCheckpointsTestnet,
	1591225230,
	3501914,
	3000 };

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
boost::assign::map_list_of(0, uint256S("0x001"));
static const Checkpoints::CCheckpointData dataRegtest = {
	&mapCheckpointsRegtest,
	1454124731,
	0,
	100 };

class CMainParams : public CChainParams
{
public:
	CMainParams()
	{
		networkID = CBaseChainParams::MAIN;
		strNetworkID = "main";

		genesis = CreateGenesisBlock(1563817096, 21770810, 0x1e0ffff0, 1, 0);
		consensus.hashGenesisBlock = genesis.GetHash();
		assert(consensus.hashGenesisBlock == uint256S("000002563024b106ca6630ff598e3016fc218f6c5f21366623bce0e75bfc2064"));
		assert(genesis.hashMerkleRoot == uint256S("b693cbb2fed7b4fbab60499202c45bf8dce6d839c2938ad0132c29dd16daa014"));

		consensus.fPowAllowMinDifficultyBlocks = false;
		consensus.powLimit = ~UINT256_ZERO >> 1;   // Guapcoin starting difficulty is 1 / 2^12
		consensus.posLimitV1 = ~UINT256_ZERO >> 24;
		consensus.posLimitV2 = ~UINT256_ZERO >> 20;
		consensus.nBudgetCycleBlocks = 9999999;       // approx. 1 every 30 days
		consensus.nBudgetFeeConfirmations = 6;      // Number of confirmations for the finalization fee
		consensus.nCoinbaseMaturity = 5;
		consensus.nFutureTimeDriftPoW = 7200;
		consensus.nFutureTimeDriftPoS = 180;
		consensus.nMasternodeCountDrift = 20;       // num of MN we allow the see-saw payments to be off by
		consensus.nMaxMoneyOut = 90000000 * COIN;
		consensus.nPoolMaxTransactions = 3;
		consensus.nProposalEstablishmentTime = 60 * 60 * 24;    // must be at least a day old to make it into a budget
		consensus.nStakeMinAge = 10 * 60;
		consensus.nStakeMinDepth = 60;
		consensus.nTargetTimespan = 40 * 60;
		consensus.nTargetTimespanV2 = 30 * 60;
		consensus.nTargetSpacing = 1 * 60;
		consensus.nTimeSlotLength = 15;

		// spork keys
		consensus.strSporkPubKey = "048aca37ab6dc31ebb9a2f4f4241f9f74f55cec1e67ed94049e50f9fb91465fefd6dbba2d2c94ff3b8b2f300601494c818f5abf719a51750dcc541e6a608afa195";
		consensus.strSporkPubKeyOld = "04cc17389379a0e323f53ea504d38cd71f43dc22f597805fed33a51b05ced1a3ae0db84089985f351b3737721736a82f58c8bd529f79c8ffe57e922bda792146ab";
		consensus.nTime_EnforceNewSporkKey = 1599195600;    //!> Friday, 4 September 2020 5:00:00 AM GMT
		consensus.nTime_RejectOldSporkKey = 1599285600;     //!> Saturday, 5 September 2020 6:00:00 AM GMT

															// Network upgrades
		consensus.vUpgrades[Consensus::BASE_NETWORK].nActivationHeight =
			Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
		consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
			Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
		consensus.vUpgrades[Consensus::UPGRADE_POS].nActivationHeight = 201;
		consensus.vUpgrades[Consensus::UPGRADE_POS_V2].nActivationHeight = 1;
		consensus.vUpgrades[Consensus::UPGRADE_BIP65].nActivationHeight = 399100;
		consensus.vUpgrades[Consensus::UPGRADE_V3_4].nActivationHeight = 400000;
		consensus.vUpgrades[Consensus::UPGRADE_V4_0].nActivationHeight = 400300;
		consensus.vUpgrades[Consensus::UPGRADE_V5_DUMMY].nActivationHeight =
			Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

		consensus.vUpgrades[Consensus::UPGRADE_BIP65].hashActivationBlock =
			uint256S("0x");
		consensus.vUpgrades[Consensus::UPGRADE_V3_4].hashActivationBlock =
			uint256S("0x");
		consensus.vUpgrades[Consensus::UPGRADE_V4_0].hashActivationBlock =
			uint256S("0x");

		/**
		* The message start string is designed to be unlikely to occur in normal data.
		* The characters are rarely used upper ASCII, not valid as UTF-8, and produce
		* a large 4-byte int at any alignment.
		*/
		pchMessageStart[0] = 0x32;
		pchMessageStart[1] = 0xcb;
		pchMessageStart[2] = 0x12;
		pchMessageStart[3] = 0xac;
		nDefaultPort = 9633;

		// Note that of those with the service bits flag, most only support a subset of possible options
		vSeeds.push_back(CDNSSeedData("dnsseeder2.guapcoin.org", "dnsseeder1.guapcoin.org", true));
		vSeeds.push_back(CDNSSeedData("dnsseeder2.guapcoin.org", "dnsseeder2.guapcoin.org", true));
		vSeeds.push_back(CDNSSeedData("seed1.guapcoin.org", "seed1.guapcoin.org", true));
		vSeeds.push_back(CDNSSeedData("seed2.guapcoin.org", "seed2.guapcoin.org", true));
		vSeeds.push_back(CDNSSeedData("seed3.guapcoin.org", "seed3.guapcoin.org", true));
		vSeeds.push_back(CDNSSeedData("seed4.guapcoin.org", "seed4.guapcoin.org", true));
		vSeeds.push_back(CDNSSeedData("seed5.guapcoin.org", "seed5.guapcoin.org", true));
		vSeeds.push_back(CDNSSeedData("seed6.guapcoin.org", "seed6.guapcoin.org", true));
		vSeeds.push_back(CDNSSeedData("seed7.guapcoin.org", "seed7.guapcoin.org", true));
		vSeeds.push_back(CDNSSeedData("seed8.guapcoin.org", "seed8.guapcoin.org", true));
		vSeeds.push_back(CDNSSeedData("seed9.guapcoin.org", "seed9.guapcoin.org", true));
		vSeeds.push_back(CDNSSeedData("seed10.guapcoin.org", "seed10.guapcoin.org", true));
		vSeeds.push_back(CDNSSeedData("guapexplorer.com", "guapexplorer.com", true));
		vSeeds.push_back(CDNSSeedData("guapcoinexplorer.com", "guapcoinexplorer.com", true));


		base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 38);
		base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 6);
		base58Prefixes[STAKING_ADDRESS] = std::vector<unsigned char>(1, 55);
		base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 46);
		base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
		base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
		// BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md
		base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0xde).convert_to_container<std::vector<unsigned char> >();

		vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

		// Sapling
		bech32HRPs[SAPLING_PAYMENT_ADDRESS] = "ps";
		bech32HRPs[SAPLING_FULL_VIEWING_KEY] = "pviews";
		bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "pivks";
		bech32HRPs[SAPLING_EXTENDED_SPEND_KEY] = "p-secret-spending-key-main";
	}

	const Checkpoints::CCheckpointData& Checkpoints() const
	{
		return data;
	}

};
static CMainParams mainParams;

/**
* Testnet (v3)
*/
class CTestNetParams : public CMainParams
{
public:
	CTestNetParams()
	{
		networkID = CBaseChainParams::TESTNET;
		strNetworkID = "test";

		genesis = CreateGenesisBlock(1454124731, 2402015, 0x1e0ffff0, 1, 250 * COIN);
		consensus.hashGenesisBlock = genesis.GetHash();
		//assert(consensus.hashGenesisBlock == uint256S("0x0000041e482b9b9691d98eefb48473405c0b8ec31b76df3797c74a78680ef818"));
		//assert(genesis.hashMerkleRoot == uint256S("0x1b2ef6e2f28be914103a277377ae7729dcd125dfeb8bf97bd5964ba72b6dc39b"));

		consensus.fPowAllowMinDifficultyBlocks = true;
		consensus.powLimit = ~UINT256_ZERO >> 20;   // Guapcoin starting difficulty is 1 / 2^12
		consensus.posLimitV1 = ~UINT256_ZERO >> 24;
		consensus.posLimitV2 = ~UINT256_ZERO >> 20;
		consensus.nBudgetCycleBlocks = 144;         // approx 10 cycles per day
		consensus.nBudgetFeeConfirmations = 3;      // (only 8-blocks window for finalization on testnet)
		consensus.nCoinbaseMaturity = 15;
		consensus.nFutureTimeDriftPoW = 7200;
		consensus.nFutureTimeDriftPoS = 180;
		consensus.nMasternodeCountDrift = 4;        // num of MN we allow the see-saw payments to be off by
		consensus.nMaxMoneyOut = 43199500 * COIN;
		consensus.nPoolMaxTransactions = 2;
		consensus.nProposalEstablishmentTime = 60 * 5;  // at least 5 min old to make it into a budget
		consensus.nStakeMinAge = 60 * 60;
		consensus.nStakeMinDepth = 100;
		consensus.nTargetTimespan = 40 * 60;
		consensus.nTargetTimespanV2 = 30 * 60;
		consensus.nTargetSpacing = 1 * 60;
		consensus.nTimeSlotLength = 15;

		// spork keys
		consensus.strSporkPubKey = "04E88BB455E2A04E65FCC41D88CD367E9CCE1F5A409BE94D8C2B4B35D223DED9C8E2F4E061349BA3A38839282508066B6DC4DB72DD432AC4067991E6BF20176127";
		consensus.strSporkPubKeyOld = "04A8B319388C0F8588D238B9941DC26B26D3F9465266B368A051C5C100F79306A557780101FE2192FE170D7E6DEFDCBEE4C8D533396389C0DAFFDBC842B002243C";
		consensus.nTime_EnforceNewSporkKey = 1566860400;    //!> August 26, 2019 11:00:00 PM GMT
		consensus.nTime_RejectOldSporkKey = 1569538800;     //!> September 26, 2019 11:00:00 PM GMT

															// Network upgrades
		consensus.vUpgrades[Consensus::BASE_NETWORK].nActivationHeight =
			Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
		consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
			Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
		consensus.vUpgrades[Consensus::UPGRADE_POS].nActivationHeight = 201;
		consensus.vUpgrades[Consensus::UPGRADE_POS_V2].nActivationHeight = 51197;
		consensus.vUpgrades[Consensus::UPGRADE_BIP65].nActivationHeight = 851019;
		consensus.vUpgrades[Consensus::UPGRADE_V3_4].nActivationHeight = 1214000;
		consensus.vUpgrades[Consensus::UPGRADE_V4_0].nActivationHeight = 1347000;
		consensus.vUpgrades[Consensus::UPGRADE_V5_DUMMY].nActivationHeight =
			Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

		consensus.vUpgrades[Consensus::UPGRADE_BIP65].hashActivationBlock =
			uint256S("0xc54b3e7e8b710e4075da1806adf2d508ae722627d5bcc43f594cf64d5eef8b30");
		consensus.vUpgrades[Consensus::UPGRADE_V3_4].hashActivationBlock =
			uint256S("0x1822577176173752aea33d1f60607cefe9e0b1c54ebaa77eb40201a385506199");
		consensus.vUpgrades[Consensus::UPGRADE_V4_0].hashActivationBlock =
			uint256S("0x30c173ffc09a13f288bf6e828216107037ce5b79536b1cebd750a014f4939882");

		/**
		* The message start string is designed to be unlikely to occur in normal data.
		* The characters are rarely used upper ASCII, not valid as UTF-8, and produce
		* a large 4-byte int at any alignment.
		*/

		pchMessageStart[0] = 0x45;
		pchMessageStart[1] = 0x76;
		pchMessageStart[2] = 0x65;
		pchMessageStart[3] = 0xba;
		nDefaultPort = 51474;

		vFixedSeeds.clear();
		vSeeds.clear();
		// nodes with support for servicebits filtering should be at the top
		vSeeds.push_back(CDNSSeedData("fuzzbawls.pw", "guapcoin-testnet.seed.fuzzbawls.pw", true));
		vSeeds.push_back(CDNSSeedData("fuzzbawls.pw", "guapcoin-testnet.seed2.fuzzbawls.pw", true));

		base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 139); // Testnet guapcoin addresses start with 'x' or 'y'
		base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 19);  // Testnet guapcoin script addresses start with '8' or '9'
		base58Prefixes[STAKING_ADDRESS] = std::vector<unsigned char>(1, 73);     // starting with 'W'
		base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);     // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
																			 // Testnet guapcoin BIP32 pubkeys start with 'DRKV'
		base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x3a)(0x80)(0x61)(0xa0).convert_to_container<std::vector<unsigned char> >();
		// Testnet guapcoin BIP32 prvkeys start with 'DRKP'
		base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x3a)(0x80)(0x58)(0x37).convert_to_container<std::vector<unsigned char> >();
		// Testnet guapcoin BIP44 coin type is '1' (All coin's testnet default)
		base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();

		vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

		// Sapling
		bech32HRPs[SAPLING_PAYMENT_ADDRESS] = "ptestsapling";
		bech32HRPs[SAPLING_FULL_VIEWING_KEY] = "pviewtestsapling";
		bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "bcktestsapling";
		bech32HRPs[SAPLING_EXTENDED_SPEND_KEY] = "p-secret-spending-key-test";
	}

	const Checkpoints::CCheckpointData& Checkpoints() const
	{
		return dataTestnet;
	}
};
static CTestNetParams testNetParams;

/**
* Regression test
*/
class CRegTestParams : public CTestNetParams
{
public:
	CRegTestParams()
	{
		networkID = CBaseChainParams::REGTEST;
		strNetworkID = "regtest";

		genesis = CreateGenesisBlock(1454124731, 2402015, 0x1e0ffff0, 1, 250 * COIN);
		consensus.hashGenesisBlock = genesis.GetHash();
		//assert(consensus.hashGenesisBlock == uint256S("0x0000041e482b9b9691d98eefb48473405c0b8ec31b76df3797c74a78680ef818"));
		//assert(genesis.hashMerkleRoot == uint256S("0x1b2ef6e2f28be914103a277377ae7729dcd125dfeb8bf97bd5964ba72b6dc39b"));

		consensus.fPowAllowMinDifficultyBlocks = true;
		consensus.powLimit = ~UINT256_ZERO >> 20;   // Guapcoin starting difficulty is 1 / 2^12
		consensus.posLimitV1 = ~UINT256_ZERO >> 24;
		consensus.posLimitV2 = ~UINT256_ZERO >> 20;
		consensus.nBudgetCycleBlocks = 144;         // approx 10 cycles per day
		consensus.nBudgetFeeConfirmations = 3;      // (only 8-blocks window for finalization on regtest)
		consensus.nCoinbaseMaturity = 100;
		consensus.nFutureTimeDriftPoW = 7200;
		consensus.nFutureTimeDriftPoS = 180;
		consensus.nMasternodeCountDrift = 4;        // num of MN we allow the see-saw payments to be off by
		consensus.nMaxMoneyOut = 43199500 * COIN;
		consensus.nPoolMaxTransactions = 2;
		consensus.nProposalEstablishmentTime = 60 * 5;  // at least 5 min old to make it into a budget
		consensus.nStakeMinAge = 0;
		consensus.nStakeMinDepth = 2;
		consensus.nTargetTimespan = 40 * 60;
		consensus.nTargetTimespanV2 = 30 * 60;
		consensus.nTargetSpacing = 1 * 60;
		consensus.nTimeSlotLength = 15;

		/* Spork Key for RegTest:
		WIF private key: 932HEevBSujW2ud7RfB1YF91AFygbBRQj3de3LyaCRqNzKKgWXi
		private key hex: bd4960dcbd9e7f2223f24e7164ecb6f1fe96fc3a416f5d3a830ba5720c84b8ca
		Address: yCvUVd72w7xpimf981m114FSFbmAmne7j9
		*/
		consensus.strSporkPubKey = "043969b1b0e6f327de37f297a015d37e2235eaaeeb3933deecd8162c075cee0207b13537618bde640879606001a8136091c62ec272dd0133424a178704e6e75bb7";
		consensus.strSporkPubKeyOld = "";
		consensus.nTime_EnforceNewSporkKey = 0;
		consensus.nTime_RejectOldSporkKey = 0;

		// Network upgrades
		consensus.vUpgrades[Consensus::BASE_NETWORK].nActivationHeight =
			Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
		consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
			Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
		consensus.vUpgrades[Consensus::UPGRADE_POS].nActivationHeight = 251;
		consensus.vUpgrades[Consensus::UPGRADE_POS_V2].nActivationHeight = 251;
		consensus.vUpgrades[Consensus::UPGRADE_BIP65].nActivationHeight =
			Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
		consensus.vUpgrades[Consensus::UPGRADE_V3_4].nActivationHeight = 251;
		consensus.vUpgrades[Consensus::UPGRADE_V4_0].nActivationHeight =
			Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
		consensus.vUpgrades[Consensus::UPGRADE_V5_DUMMY].nActivationHeight = 300;

		/**
		* The message start string is designed to be unlikely to occur in normal data.
		* The characters are rarely used upper ASCII, not valid as UTF-8, and produce
		* a large 4-byte int at any alignment.
		*/

		pchMessageStart[0] = 0xa1;
		pchMessageStart[1] = 0xcf;
		pchMessageStart[2] = 0x7e;
		pchMessageStart[3] = 0xac;
		nDefaultPort = 51476;

		vFixedSeeds.clear(); //! Testnet mode doesn't have any fixed seeds.
		vSeeds.clear();      //! Testnet mode doesn't have any DNS seeds.
	}

	const Checkpoints::CCheckpointData& Checkpoints() const
	{
		return dataRegtest;
	}

	void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
	{
		assert(idx > Consensus::BASE_NETWORK && idx < Consensus::MAX_NETWORK_UPGRADES);
		consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
	}
};
static CRegTestParams regTestParams;

static CChainParams* pCurrentParams = 0;

const CChainParams& Params()
{
	assert(pCurrentParams);
	return *pCurrentParams;
}

CChainParams& Params(CBaseChainParams::Network network)
{
	switch (network) {
	case CBaseChainParams::MAIN:
		return mainParams;
	case CBaseChainParams::TESTNET:
		return testNetParams;
	case CBaseChainParams::REGTEST:
		return regTestParams;
	default:
		assert(false && "Unimplemented network");
		return mainParams;
	}
}

void SelectParams(CBaseChainParams::Network network)
{
	SelectBaseParams(network);
	pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
	CBaseChainParams::Network network = NetworkIdFromCommandLine();
	if (network == CBaseChainParams::MAX_NETWORK_TYPES)
		return false;

	SelectParams(network);
	return true;
}

void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
	regTestParams.UpdateNetworkUpgradeParameters(idx, nActivationHeight);
}
