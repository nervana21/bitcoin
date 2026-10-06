// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsbase.h>
#include <common/args.h>
#include <consensus/params.h>
#include <deploymentinfo.h>
#include <tinyformat.h>
#include <util/chaintype.h>
#include <util/log.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <cassert>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

using util::SplitString;

static void HandleDeploymentArgs(const ArgsManager& args, CChainParams::DeploymentOptions& options)
{
    for (const std::string& arg : args.GetArgs("-testactivationheight")) {
        const auto found{arg.find('@')};
        if (found == std::string::npos) {
            throw std::runtime_error(strprintf("Invalid format (%s) for -testactivationheight=name@height.", arg));
        }

        const auto value{arg.substr(found + 1)};
        const auto height{ToIntegral<int32_t>(value)};
        if (!height || *height < 0 || *height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid height value (%s) for -testactivationheight=name@height.", arg));
        }

        const auto deployment_name{arg.substr(0, found)};
        if (const auto buried_deployment = GetBuriedDeployment(deployment_name)) {
            options.activation_heights[*buried_deployment] = *height;
        } else {
            throw std::runtime_error(strprintf("Invalid name (%s) for -testactivationheight=name@height.", arg));
        }
    }

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams = SplitString(strDeployment, ':');
        if (vDeploymentParams.size() < 3 || 4 < vDeploymentParams.size()) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end[:min_activation_height]");
        }
        CChainParams::VersionBitsParameters vbparams{};
        const auto start_time{ToIntegral<int64_t>(vDeploymentParams[1])};
        if (!start_time) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        vbparams.start_time = *start_time;
        const auto timeout{ToIntegral<int64_t>(vDeploymentParams[2])};
        if (!timeout) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        vbparams.timeout = *timeout;
        if (vDeploymentParams.size() >= 4) {
            const auto min_activation_height{ToIntegral<int64_t>(vDeploymentParams[3])};
            if (!min_activation_height) {
                throw std::runtime_error(strprintf("Invalid min_activation_height (%s)", vDeploymentParams[3]));
            }
            vbparams.min_activation_height = *min_activation_height;
        } else {
            vbparams.min_activation_height = 0;
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                options.version_bits_parameters[Consensus::DeploymentPos(j)] = vbparams;
                found = true;
                LogInfo("Setting version bits activation parameters for %s to start=%ld, timeout=%ld, min_activation_height=%d",
                        vDeploymentParams[0], vbparams.start_time, vbparams.timeout, vbparams.min_activation_height);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

void ReadMainNetArgs(const ArgsManager& args, CChainParams::MainNetOptions& options)
{
    HandleDeploymentArgs(args, options.dep_opts);
}

void ReadTestNetArgs(const ArgsManager& args, CChainParams::TestNetOptions& options)
{
    HandleDeploymentArgs(args, options.dep_opts);
}

void ReadSigNetArgs(const ArgsManager& args, CChainParams::SigNetOptions& options)
{
    if (!args.GetArgs("-signetseednode").empty()) {
        options.seeds.emplace(args.GetArgs("-signetseednode"));
    }
    if (!args.GetArgs("-signetchallenge").empty()) {
        const auto signet_challenge = args.GetArgs("-signetchallenge");
        if (signet_challenge.size() != 1) {
            throw std::runtime_error("-signetchallenge cannot be multiple values.");
        }
        const auto val{TryParseHex<uint8_t>(signet_challenge[0])};
        if (!val) {
            throw std::runtime_error(strprintf("-signetchallenge must be hex, not '%s'.", signet_challenge[0]));
        }
        options.challenge.emplace(*val);
    }
    HandleDeploymentArgs(args, options.dep_opts);
}

void ReadRegTestArgs(const ArgsManager& args, CChainParams::RegTestOptions& options)
{
    if (auto value = args.GetBoolArg("-fastprune")) options.fastprune = *value;
    if (HasTestOption(args, "bip94")) options.enforce_bip94 = true;

    HandleDeploymentArgs(args, options.dep_opts);
}

static std::vector<AssumeutxoData> MainAssumeutxo()
{
    return {
        {
            .height = 840'000,
            .hash_serialized = AssumeutxoHash{uint256{"a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96"}},
            .m_chain_tx_count = 991032194,
            .blockhash = uint256{"0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"},
        },
        {
            .height = 880'000,
            .hash_serialized = AssumeutxoHash{uint256{"dbd190983eaf433ef7c15f78a278ae42c00ef52e0fd2a54953782175fbadcea9"}},
            .m_chain_tx_count = 1145604538,
            .blockhash = uint256{"000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880"},
        },
        {
            .height = 910'000,
            .hash_serialized = AssumeutxoHash{uint256{"4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568"}},
            .m_chain_tx_count = 1226586151,
            .blockhash = uint256{"0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821"},
        },
        {
            .height = 935'000,
            .hash_serialized = AssumeutxoHash{uint256{"e4b90ef9eae834f56c4b64d2d50143cee10ad87994c614d7d04125e2a6025050"}},
            .m_chain_tx_count = 1305397408,
            .blockhash = uint256{"0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee"},
        },
        {
            .height = 965'000,
            .hash_serialized = AssumeutxoHash{uint256{"4a8d794337118c0c615b574f817c7306c687584a537184b8d233df42bf477ec2"}},
            .m_chain_tx_count = 1429611231,
            .blockhash = uint256{"00000000000000000001595977e6000ce56129f5c9b4073e31ccc30b90b97da9"},
        },
    };
}

static std::vector<AssumeutxoData> TestNetAssumeutxo()
{
    return {
        {
            .height = 2'500'000,
            .hash_serialized = AssumeutxoHash{uint256{"f841584909f68e47897952345234e37fcd9128cd818f41ee6c3ca68db8071be7"}},
            .m_chain_tx_count = 66484552,
            .blockhash = uint256{"0000000000000093bcb68c03a9a168ae252572d348a2eaeba2cdf9231d73206f"},
        },
        {
            .height = 4'840'000,
            .hash_serialized = AssumeutxoHash{uint256{"ce6bb677bb2ee9789c4a1c9d73e6683c53fc20e8fdbedbdaaf468982a0c8db2a"}},
            .m_chain_tx_count = 536078574,
            .blockhash = uint256{"00000000000000f4971a7fb37fbdff89315b69a2e1920c467654a382f0d64786"},
        },
        {
            .height = 5'125'000,
            .hash_serialized = AssumeutxoHash{uint256{"d05430f34c9b7dd7eb98c0718cdf03782bcce8273847557d68ac2efc1365d4b8"}},
            .m_chain_tx_count = 536708663,
            .blockhash = uint256{"00000000000009ad1946e21cb4f1a6323ee99c89017b59d5166472672b868133"},
        },
    };
}

static std::vector<AssumeutxoData> TestNet4Assumeutxo()
{
    return {
        {
            .height = 90'000,
            .hash_serialized = AssumeutxoHash{uint256{"784fb5e98241de66fdd429f4392155c9e7db5c017148e66e8fdbc95746f8b9b5"}},
            .m_chain_tx_count = 11347043,
            .blockhash = uint256{"0000000002ebe8bcda020e0dd6ccfbdfac531d2f6a81457191b99fc2df2dbe3b"},
        },
        {
            .height = 120'000,
            .hash_serialized = AssumeutxoHash{uint256{"10b05d05ad468d0971162e1b222a4aa66caca89da2bb2a93f8f37fb29c4794b0"}},
            .m_chain_tx_count = 14141057,
            .blockhash = uint256{"000000000bd2317e51b3c5794981c35ba894ce27d3e772d5c39ecd9cbce01dc8"},
        },
        {
            .height = 150'000,
            .hash_serialized = AssumeutxoHash{uint256{"ca068cae50679d7c947454bbe4f0e6aeec1fbe2c6c2735a08bb988623649f950"}},
            .m_chain_tx_count = 14810011,
            .blockhash = uint256{"0000000000d9877342754dea8ec1eb24631517d38e3443c370465ee53a8b7434"},
        },
    };
}

static std::vector<AssumeutxoData> SigNetAssumeutxo()
{
    return {
        {
            .height = 160'000,
            .hash_serialized = AssumeutxoHash{uint256{"fe0a44309b74d6b5883d246cb419c6221bcccf0b308c9b59b7d70783dbdf928a"}},
            .m_chain_tx_count = 2289496,
            .blockhash = uint256{"0000003ca3c99aff040f2563c2ad8f8ec88bd0fd6b8f0895cfaf1ef90353a62c"},
        },
        {
            .height = 290'000,
            .hash_serialized = AssumeutxoHash{uint256{"97267e000b4b876800167e71b9123f1529d13b14308abec2888bbd2160d14545"}},
            .m_chain_tx_count = 28547497,
            .blockhash = uint256{"0000000577f2741bb30cd9d39d6d71b023afbeb9764f6260786a97969d5c9ac0"},
        },
        {
            .height = 320'000,
            .hash_serialized = AssumeutxoHash{uint256{"1aaf72ecb376cc16957fbb8d5d406bfd6e3165510e2fc83879b6d14cd20b4462"}},
            .m_chain_tx_count = 32079110,
            .blockhash = uint256{"0000000740ae66b284da84387dcfa14d7b1385b0bad482005ba4e770ea6c4b95"},
        },
    };
}

static std::vector<AssumeutxoData> RegTestAssumeutxo()
{
    return {
        {   // For use by unit tests
            .height = 110,
            .hash_serialized = AssumeutxoHash{uint256{"86e9a1205b418b16dde3a18a78c730e30137e28466bda5dbf6b33ab8fc05447c"}},
            .m_chain_tx_count = 111,
            .blockhash = uint256{"135eec25a6fb277884e5824e7aa7d052c4868161c99a5122170b5266f86c273d"},
        },
        {
            // For use by fuzz target src/test/fuzz/utxo_snapshot.cpp
            .height = 200,
            .hash_serialized = AssumeutxoHash{uint256{"17dcc016d188d16068907cdeb38b75691a118d43053b8cd6a25969419381d13a"}},
            .m_chain_tx_count = 201,
            .blockhash = uint256{"385901ccbd69dff6bbd00065d01fb8a9e464dede7cfe0372443884f9b1dcf6b9"},
        },
        {
            // For use by test/functional/feature_assumeutxo.py and test/functional/tool_bitcoin_chainstate.py
            .height = 299,
            .hash_serialized = AssumeutxoHash{uint256{"106b2c56233e378a824cf0d5ff2be42ed32c72f1605c9be288d00942908a40ac"}},
            .m_chain_tx_count = 334,
            .blockhash = uint256{"0c552ced4721c249a389eb9b08cb8da261cd46f0e7b5f9d064d48f3113406853"},
        },
    };
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const ChainType chain)
{
    switch (chain) {
    case ChainType::MAIN: {
        auto opts = CChainParams::MainNetOptions{};
        ReadMainNetArgs(args, opts);
        opts.assume_valid = uint256{"00000000000000000000748969ec33043c0e52a763c6dd5193861f559f2c72e3"}; // 966143
        opts.assumeutxo = MainAssumeutxo();
        return CChainParams::Main(opts);
    }
    case ChainType::TESTNET: {
        auto opts = CChainParams::TestNetOptions{};
        ReadTestNetArgs(args, opts);
        opts.assume_valid = uint256{"00000000b318a3703d14a844c55ef507f4c2fc8f8766e24271fd43c180c51637"}; // 5128859
        opts.assumeutxo = TestNetAssumeutxo();
        return CChainParams::TestNet(opts);
    }
    case ChainType::TESTNET4: {
        auto opts = CChainParams::TestNetOptions{};
        ReadTestNetArgs(args, opts);
        opts.assume_valid = uint256{"0000000021df65b91665a342e26ceb05e54826ad7d8fcd40316230058fa3b865"}; // 151604
        opts.assumeutxo = TestNet4Assumeutxo();
        return CChainParams::TestNet4(opts);
    }
    case ChainType::SIGNET: {
        auto opts = CChainParams::SigNetOptions{};
        ReadSigNetArgs(args, opts);
        if (!opts.challenge) {
            opts.assume_valid = uint256{"00000002a5e0ba0498f1e9f4591af0b66b63c654665efe65206fd0ae7bbaf923"}; // 321295
        }
        opts.assumeutxo = SigNetAssumeutxo();
        return CChainParams::SigNet(opts);
    }
    case ChainType::REGTEST: {
        auto opts = CChainParams::RegTestOptions{};
        ReadRegTestArgs(args, opts);
        opts.assumeutxo = RegTestAssumeutxo();
        return CChainParams::RegTest(opts);
    }
    }
    assert(false);
}

void SelectParams(const ChainType chain)
{
    SelectBaseParams(chain);
    globalChainParams = CreateChainParams(gArgs, chain);
}
