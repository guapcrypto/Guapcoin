// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2019 The PIVX developers
// Copyright (c) 2019-2020 The Guapcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"
#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>
#include <limits>

#include "chainparamsseeds.h"

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
    genesis.hashPrevBlock = 0;
    genesis.nVersion = nVersion;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
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

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress>& vSeedsOut, const SeedSpec6* data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7 * 24 * 60 * 60;
    for (unsigned int i = 0; i < count; i++) {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

//   What makes a good checkpoint block?
// + Is surrounded by blocks with reasonable timestamps
//   (no blocks before with a timestamp after, none after with
//    timestamp before)
// + Contains no strange transactions
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
	;
static const Checkpoints::CCheckpointData data = {
    &mapCheckpoints,
	1591602525, // * UNIX timestamp of last checkpoint block
	917676,     // * total number of transactions between genesis and last checkpoint
                //   (the tx=... number in the SetBestChain debug.log lines)
    2000        // * estimated number of transactions per day after checkpoint
};

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
    boost::assign::map_list_of
    (0, uint256("0x001"));
static const Checkpoints::CCheckpointData dataTestnet = {
    &mapCheckpointsTestnet,
    1575145155,
    2971390,
    250};

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
    boost::assign::map_list_of(0, uint256("0x001"));
static const Checkpoints::CCheckpointData dataRegtest = {
    &mapCheckpointsRegtest,
    1454124731,
    0,
    100};

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";

        genesis = CreateGenesisBlock(1563817096, 21770810, 0x1e0ffff0, 1, 0 * COIN);
		consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256("0x000002563024b106ca6630ff598e3016fc218f6c5f21366623bce0e75bfc2064"));
        assert(genesis.hashMerkleRoot == uint256("0xb693cbb2fed7b4fbab60499202c45bf8dce6d839c2938ad0132c29dd16daa014"));

        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.powLimit   = ~uint256(0) >> 1;   // Guapcoin starting difficulty is 1 / 2^12
        consensus.posLimitV1 = ~uint256(0) >> 24;
        consensus.posLimitV2 = ~uint256(0) >> 20;
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
        consensus.strObfuscationPoolDummyAddress = "GSfaHsKBwdi7d4xeXCgQ3tzNkWzvxchSjN";

        // spork keys
        consensus.strSporkPubKey = "048aca37ab6dc31ebb9a2f4f4241f9f74f55cec1e67ed94049e50f9fb91465fefd6dbba2d2c94ff3b8b2f300601494c818f5abf719a51750dcc541e6a608afa195";
        consensus.strSporkPubKeyOld = "04cc17389379a0e323f53ea504d38cd71f43dc22f597805fed33a51b05ced1a3ae0db84089985f351b3737721736a82f58c8bd529f79c8ffe57e922bda792146ab";
        consensus.nTime_EnforceNewSporkKey = 1586509200;    //!> 10 April 2020 09:00:00 AM GMT
        consensus.nTime_RejectOldSporkKey = 1588150800;     //!> 29 April 2020 09:00:00 AM GMT

        // majorities for block version upgrades
        consensus.nEnforceBlockUpgradeMajority = 750; // 75%
        consensus.nRejectBlockOutdatedMajority = 950; // 95%
        consensus.nToCheckBlockUpgradeMajority = 1000; // Approximate expected amount of blocks in 7 days (1440*7.5)

		// height-based activations
		consensus.height_last_PoW = 200;
		consensus.height_start_BIP65 = 399100;             // 82629b7a9978f5c7ea3f70a12db92633a7d2e436711500db28b97efd48b1e527
		consensus.height_start_InvalidUTXOsCheck = 999999999;
		consensus.height_start_MessSignaturesV2 = 400300;  // TimeProtocolV2, Blocks V7 and newMessageSignatures
		consensus.height_start_StakeModifierNewSelection = 1;
		consensus.height_start_StakeModifierV2 = 400000;
		consensus.height_start_TimeProtoV2 = 400300;    // TimeProtocolV2, Blocks V7 and newMessageSignatures

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
		vSeeds.push_back(CDNSSeedData("159.65.221.180", "159.65.221.180"));
		vSeeds.push_back(CDNSSeedData("45.76.61.148", "45.76.61.148"));
		vSeeds.push_back(CDNSSeedData("2001:19f0:5401:41f:5400:02ff:feab:b408", "2001:19f0:5401:41f:5400:02ff:feab:b408"));
		vSeeds.push_back(CDNSSeedData("209.250.250.121", "209.250.250.121"));
		vSeeds.push_back(CDNSSeedData("2001:19f0:5001:331b:5400:02ff:fea5:3f49", "2001:19f0:5001:331b:5400:02ff:fea5:3f49"));
		vSeeds.push_back(CDNSSeedData("136.244.112.117", "136.244.112.117"));    
		vSeeds.push_back(CDNSSeedData("2001:19f0:6801:fcb:5400:02ff:fea5:3f5f", "2001:19f0:6801:fcb:5400:02ff:fea5:3f5f"));
		vSeeds.push_back(CDNSSeedData("199.247.20.128", "199.247.20.128"));
		vSeeds.push_back(CDNSSeedData("2001:19f0:6c01:27ea:5400:02ff:fea5:3f65", "2001:19f0:6c01:27ea:5400:02ff:fea5:3f65"));
		vSeeds.push_back(CDNSSeedData("78.141.203.208", "78.141.203.208"));
		vSeeds.push_back(CDNSSeedData("2001:19f0:7400:8dfc:5400:02ff:fea5:3f81", "2001:19f0:7400:8dfc:5400:02ff:fea5:3f81"));
		vSeeds.push_back(CDNSSeedData("155.138.140.38", "155.138.140.38"));
		vSeeds.push_back(CDNSSeedData("2001:19f0:b001:7d:5400:02ff:fea5:3f89", "2001:19f0:b001:7d:5400:02ff:fea5:3f89"));
		vSeeds.push_back(CDNSSeedData("45.76.199.11", "45.76.199.11"));
		vSeeds.push_back(CDNSSeedData("2401:c080:1000:4290:5400:02ff:fea5:3f95", "2401:c080:1000:4290:5400:02ff:fea5:3f95"));
		vSeeds.push_back(CDNSSeedData("45.63.25.141", "45.63.25.141"));
		vSeeds.push_back(CDNSSeedData("2401:c080:1800:4a1a:5400:02ff:fea5:3f9c", "2401:c080:1800:4a1a:5400:02ff:fea5:3f9c"));
		vSeeds.push_back(CDNSSeedData("108.61.252.179", "108.61.252.179"));
		vSeeds.push_back(CDNSSeedData("155.138.219.187", "155.138.219.187"));
		vSeeds.push_back(CDNSSeedData("66.42.93.170", "66.42.93.170"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 38);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 6);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 46);
		base58Prefixes[STAKING_ADDRESS] = std::vector<unsigned char>(1, 55);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        // BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0xde).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));
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
        //assert(consensus.hashGenesisBlock == uint256("0x0000041e482b9b9691d98eefb48473405c0b8ec31b76df3797c74a78680ef818"));
        //assert(genesis.hashMerkleRoot == uint256("0x1b2ef6e2f28be914103a277377ae7729dcd125dfeb8bf97bd5964ba72b6dc39b"));

        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.powLimit   = ~uint256(0) >> 20;   // Guapcoin starting difficulty is 1 / 2^12
        consensus.posLimitV1 = ~uint256(0) >> 24;
        consensus.posLimitV2 = ~uint256(0) >> 20;
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
        consensus.strObfuscationPoolDummyAddress = "y57cqfGRkekRyDRNeJiLtYVEbvhXrNbmox";

        // spork keys
        consensus.strSporkPubKey = "048aca37ab6dc31ebb9a2f4f4241f9f74f55cec1e67ed94049e50f9fb91465fefd6dbba2d2c94ff3b8b2f300601494c818f5abf719a51750dcc541e6a608afa195";
        consensus.strSporkPubKeyOld = "048aca37ab6dc31ebb9a2f4f4241f9f74f55cec1e67ed94049e50f9fb91465fefd6dbba2d2c94ff3b8b2f300601494c818f5abf719a51750dcc541e6a608afa195";
        consensus.nTime_EnforceNewSporkKey = 1566860400;    //!> August 26, 2019 11:00:00 PM GMT
        consensus.nTime_RejectOldSporkKey = 1569538800;     //!> September 26, 2019 11:00:00 PM GMT

        // majorities for block version upgrades
        consensus.nEnforceBlockUpgradeMajority = 4320; // 75%
        consensus.nRejectBlockOutdatedMajority = 5472; // 95%
        consensus.nToCheckBlockUpgradeMajority = 5760; // 4 days

        // height based activations
        consensus.height_last_PoW = 200;
        consensus.height_start_BIP65 = 851019;
        consensus.height_start_InvalidUTXOsCheck = 999999999;
        consensus.height_start_MessSignaturesV2 = 1347000;      // TimeProtocolV2, Blocks V7 and newMessageSignatures
        consensus.height_start_StakeModifierNewSelection = 51197;
        consensus.height_start_StakeModifierV2 = 1214000;
        consensus.height_start_TimeProtoV2 = 1347000;           // TimeProtocolV2, Blocks V7 and newMessageSignatures

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
        vSeeds.push_back(CDNSSeedData("fuzzbawls.pw", "guapcoin-testnet.seed.fuzzbawls.pw"));
        vSeeds.push_back(CDNSSeedData("fuzzbawls.pw", "guapcoin-testnet.seed2.fuzzbawls.pw"));
        vSeeds.push_back(CDNSSeedData("warrows.dev", "testnet.dnsseed.guapcoin.warrows.dev"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 139); // Testnet guapcoin addresses start with 'x' or 'y'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 19);  // Testnet guapcoin script addresses start with '8' or '9'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);     // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        // Testnet guapcoin BIP32 pubkeys start with 'DRKV'
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x3a)(0x80)(0x61)(0xa0).convert_to_container<std::vector<unsigned char> >();
        // Testnet guapcoin BIP32 prvkeys start with 'DRKP'
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x3a)(0x80)(0x58)(0x37).convert_to_container<std::vector<unsigned char> >();
        // Testnet guapcoin BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));
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
        //assert(consensus.hashGenesisBlock == uint256("0x0000041e482b9b9691d98eefb48473405c0b8ec31b76df3797c74a78680ef818"));
        //assert(genesis.hashMerkleRoot == uint256("0x1b2ef6e2f28be914103a277377ae7729dcd125dfeb8bf97bd5964ba72b6dc39b"));

        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.powLimit   = ~uint256(0) >> 20;   // Guapcoin starting difficulty is 1 / 2^12
        consensus.posLimitV1 = ~uint256(0) >> 24;
        consensus.posLimitV2 = ~uint256(0) >> 20;
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
        consensus.nStakeMinDepth = 0;
        consensus.nTargetTimespan = 40 * 60;
        consensus.nTargetTimespanV2 = 30 * 60;
        consensus.nTargetSpacing = 1 * 60;
        consensus.nTimeSlotLength = 15;
        consensus.strObfuscationPoolDummyAddress = "y57cqfGRkekRyDRNeJiLtYVEbvhXrNbmox";

        /* Spork Key for RegTest:
        WIF private key: 932HEevBSujW2ud7RfB1YF91AFygbBRQj3de3LyaCRqNzKKgWXi
        private key hex: bd4960dcbd9e7f2223f24e7164ecb6f1fe96fc3a416f5d3a830ba5720c84b8ca
        Address: yCvUVd72w7xpimf981m114FSFbmAmne7j9
        */
        consensus.strSporkPubKey = "043969b1b0e6f327de37f297a015d37e2235eaaeeb3933deecd8162c075cee0207b13537618bde640879606001a8136091c62ec272dd0133424a178704e6e75bb7";
        consensus.strSporkPubKeyOld = "";
        consensus.nTime_EnforceNewSporkKey = 0;
        consensus.nTime_RejectOldSporkKey = 0;

        // majorities for block version upgrades
        consensus.nEnforceBlockUpgradeMajority = 750;
        consensus.nRejectBlockOutdatedMajority = 950;
        consensus.nToCheckBlockUpgradeMajority = 1000;

        // height based activations
        consensus.height_last_PoW = 250;
        consensus.height_start_BIP65 = 851019;              // Not defined for regtest. Inherit TestNet value.
        consensus.height_start_InvalidUTXOsCheck = 999999999;
        consensus.height_start_MessSignaturesV2 = 1;
        consensus.height_start_StakeModifierNewSelection = 0;
        consensus.height_start_StakeModifierV2 = 251;       // start with modifier V2 on regtest
        consensus.height_start_TimeProtoV2 = 999999999;


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
