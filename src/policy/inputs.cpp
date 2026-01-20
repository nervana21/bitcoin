// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/policy.h>

#include <coins.h>
#include <consensus/validation.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/solver.h>
#include <span.h>
#include <tinyformat.h>
#include <util/check.h>

#include <vector>

/**
 * Check the total number of non-witness sigops across the whole transaction, as per BIP54.
 */
static bool CheckSigopsBIP54(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    Assert(!tx.IsCoinBase());

    unsigned int sigops{0};
    for (const auto& txin: tx.vin) {
        const auto& prev_txo{inputs.AccessCoin(txin.prevout).out};

        // Unlike the existing block wide sigop limit which counts sigops present in the block
        // itself (including the scriptPubKey which is not executed until spending later), BIP54
        // counts sigops in the block where they are potentially executed (only).
        // This means sigops in the spent scriptPubKey count toward the limit.
        // `fAccurate` means correctly accounting sigops for CHECKMULTISIGs(VERIFY) with 16 pubkeys
        // or fewer. This method of accounting was introduced by BIP16, and BIP54 reuses it.
        // The GetSigOpCount call on the previous scriptPubKey counts both bare and P2SH sigops.
        sigops += txin.scriptSig.GetSigOpCount(/*fAccurate=*/true);
        sigops += prev_txo.scriptPubKey.GetSigOpCount(txin.scriptSig);

        if (sigops > MAX_TX_BIP54_SIGOPS) {
            return false;
        }
    }

    return true;
}

/**
 * Check transaction inputs.
 *
 * This does three things:
 *  * Prevents mempool acceptance of spends of future
 *    segwit versions we don't know how to validate
 *  * Mitigates a potential denial-of-service attack with
 *    P2SH scripts with a crazy number of expensive
 *    CHECKSIG/CHECKMULTISIG operations.
 *  * Prevents spends of unknown/irregular scriptPubKeys,
 *    which mitigates potential denial-of-service attacks
 *    involving expensive scripts and helps reserve them
 *    as potential new upgrade hooks.
 *
 * Note that only the non-witness portion of the transaction is checked here.
 *
 * We also check the total number of non-witness sigops across the whole transaction, as per BIP54.
 */
TxValidationState ValidateInputsStandardness(const CTransaction& tx, const CCoinsViewCache& mapInputs)
{
    TxValidationState state;
    if (tx.IsCoinBase()) {
        return state; // Coinbases don't use vin normally
    }

    if (!CheckSigopsBIP54(tx, mapInputs)) {
        state.Invalid(TxValidationResult::TX_INPUTS_NOT_STANDARD, "bad-txns-nonstandard-inputs", "non-witness sigops exceed bip54 limit");
        return state;
    }

    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const CTxOut& prev = mapInputs.AccessCoin(tx.vin[i].prevout).out;

        std::vector<std::vector<unsigned char> > vSolutions;
        TxoutType whichType = Solver(prev.scriptPubKey, vSolutions);
        if (whichType == TxoutType::NONSTANDARD) {
            state.Invalid(TxValidationResult::TX_INPUTS_NOT_STANDARD, "bad-txns-nonstandard-inputs", strprintf("input %u script unknown", i));
            return state;
        } else if (whichType == TxoutType::WITNESS_UNKNOWN) {
            // WITNESS_UNKNOWN failures are typically also caught with a policy
            // flag in the script interpreter, but it can be helpful to catch
            // this type of NONSTANDARD transaction earlier in transaction
            // validation.
            state.Invalid(TxValidationResult::TX_INPUTS_NOT_STANDARD, "bad-txns-nonstandard-inputs", strprintf("input %u witness program is undefined", i));
            return state;
        } else if (whichType == TxoutType::SCRIPTHASH) {
            std::vector<std::vector<unsigned char> > stack;
            ScriptError serror;
            // convert the scriptSig into a stack, so we can inspect the redeemScript
            if (!EvalScript(stack, tx.vin[i].scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SigVersion::BASE, &serror)) {
                state.Invalid(TxValidationResult::TX_INPUTS_NOT_STANDARD, "bad-txns-nonstandard-inputs", strprintf("p2sh scriptsig malformed (input %u: %s)", i, ScriptErrorString(serror)));
                return state;
            }
            if (stack.empty()) {
                state.Invalid(TxValidationResult::TX_INPUTS_NOT_STANDARD, "bad-txns-nonstandard-inputs", strprintf("input %u P2SH redeemscript missing", i));
                return state;
            }
            CScript subscript(stack.back().begin(), stack.back().end());
            unsigned int sigop_count = subscript.GetSigOpCount(true);
            if (sigop_count > MAX_P2SH_SIGOPS) {
                state.Invalid(TxValidationResult::TX_INPUTS_NOT_STANDARD, "bad-txns-nonstandard-inputs", strprintf("p2sh redeemscript sigops exceed limit (input %u: %u > %u)", i, sigop_count, MAX_P2SH_SIGOPS));
                return state;
            }
        }
    }

    return state;
}

bool IsWitnessStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs)
{
    if (tx.IsCoinBase())
        return true; // Coinbases are skipped

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        // We don't care if witness for this input is empty, since it must not be bloated.
        // If the script is invalid without witness, it would be caught sooner or later during validation.
        if (tx.vin[i].scriptWitness.IsNull())
            continue;

        const CTxOut &prev = mapInputs.AccessCoin(tx.vin[i].prevout).out;

        // get the scriptPubKey corresponding to this input:
        CScript prevScript = prev.scriptPubKey;

        // witness stuffing detected
        if (prevScript.IsPayToAnchor()) {
            return false;
        }

        bool p2sh = false;
        if (prevScript.IsPayToScriptHash()) {
            std::vector <std::vector<unsigned char> > stack;
            // If the scriptPubKey is P2SH, we try to extract the redeemScript casually by converting the scriptSig
            // into a stack. We do not check IsPushOnly nor compare the hash as these will be done later anyway.
            // If the check fails at this stage, we know that this txid must be a bad one.
            if (!EvalScript(stack, tx.vin[i].scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SigVersion::BASE))
                return false;
            if (stack.empty())
                return false;
            prevScript = CScript(stack.back().begin(), stack.back().end());
            p2sh = true;
        }

        int witnessversion = 0;
        std::vector<unsigned char> witnessprogram;

        // Non-witness program must not be associated with any witness
        if (!prevScript.IsWitnessProgram(witnessversion, witnessprogram))
            return false;

        // Check P2WSH standard limits
        if (witnessversion == 0 && witnessprogram.size() == WITNESS_V0_SCRIPTHASH_SIZE) {
            if (tx.vin[i].scriptWitness.stack.back().size() > MAX_STANDARD_P2WSH_SCRIPT_SIZE)
                return false;
            size_t sizeWitnessStack = tx.vin[i].scriptWitness.stack.size() - 1;
            if (sizeWitnessStack > MAX_STANDARD_P2WSH_STACK_ITEMS)
                return false;
            for (unsigned int j = 0; j < sizeWitnessStack; j++) {
                if (tx.vin[i].scriptWitness.stack[j].size() > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE)
                    return false;
            }
        }

        // Check policy limits for Taproot spends:
        // - MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE limit for stack item size
        // - No annexes
        if (witnessversion == 1 && witnessprogram.size() == WITNESS_V1_TAPROOT_SIZE && !p2sh) {
            // Taproot spend (non-P2SH-wrapped, version 1, witness program size 32; see BIP 341)
            std::span stack{tx.vin[i].scriptWitness.stack};
            if (stack.size() >= 2 && !stack.back().empty() && stack.back()[0] == ANNEX_TAG) {
                // Annexes are nonstandard as long as no semantics are defined for them.
                return false;
            }
            if (stack.size() >= 2) {
                // Script path spend (2 or more stack elements after removing optional annex)
                const auto& control_block = SpanPopBack(stack);
                SpanPopBack(stack); // Ignore script
                if (control_block.empty()) return false; // Empty control block is invalid
                if ((control_block[0] & TAPROOT_LEAF_MASK) == TAPROOT_LEAF_TAPSCRIPT) {
                    // Leaf version 0xc0 (aka Tapscript, see BIP 342)
                    for (const auto& item : stack) {
                        if (item.size() > MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE) return false;
                    }
                }
            } else if (stack.size() == 1) {
                // Key path spend (1 stack element after removing optional annex)
                // (no policy rules apply)
            } else {
                // 0 stack elements; this is already invalid by consensus rules
                return false;
            }
        }
    }
    return true;
}

bool SpendsNonAnchorWitnessProg(const CTransaction& tx, const CCoinsViewCache& prevouts)
{
    if (tx.IsCoinBase()) {
        return false;
    }

    int version;
    std::vector<uint8_t> program;
    for (const auto& txin: tx.vin) {
        const auto& prev_spk{prevouts.AccessCoin(txin.prevout).out.scriptPubKey};

        // Note this includes not-yet-defined witness programs.
        if (prev_spk.IsWitnessProgram(version, program) && !prev_spk.IsPayToAnchor(version, program)) {
            return true;
        }

        // For P2SH extract the redeem script and check if it spends a non-Taproot witness program. Note
        // this is fine to call EvalScript (as done in ValidateInputsStandardness/IsWitnessStandard) because this
        // function is only ever called after IsStandardTx, which checks the scriptsig is pushonly.
        if (prev_spk.IsPayToScriptHash()) {
            // If EvalScript fails or results in an empty stack, the transaction is invalid by consensus.
            std::vector <std::vector<uint8_t>> stack;
            if (!EvalScript(stack, txin.scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, SigVersion::BASE)
                || stack.empty()) {
                continue;
            }
            const CScript redeem_script{stack.back().begin(), stack.back().end()};
            if (redeem_script.IsWitnessProgram(version, program)) {
                return true;
            }
        }
    }

    return false;
}

