from typing import OrderedDict
from embit import bip32, bip39, compact
from embit.liquid.networks import get_network
from embit.liquid import slip77
from embit.descriptor.checksum import add_checksum
from embit.descriptor import Descriptor
from embit.liquid.pset import PSET
from embit.liquid.finalizer import finalize_psbt
from embit.liquid.transaction import LSIGHASH as SIGHASH
import random
import pytest
import hashlib
import json
import requests
import math

# PSET key for asset metadata
PSBT_ELEMENTS_HWW_GLOBAL_ASSET_METADATA = b'\xfc\x08pset_hww\x00'

# liquid regtest can have any name except main, test, regtest, liquidv1 and liquidtestnet
NET = get_network("liquidregtest")

MNEMONIC = "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"
SEED = bip39.mnemonic_to_seed(MNEMONIC)
ROOTKEY = bip32.HDKey.from_seed(SEED, version=NET["xprv"])
FGP = ROOTKEY.my_fingerprint.hex() # fingerprint for derivation
MBK = slip77.master_blinding_from_seed(SEED) # master blinding key
MBK_SLIP77 = f"slip77({MBK.secret.hex()})" # MBK formatted according to ELIP 150
CONTRACT_VERSION = 0
ISSUE_FEE = 1000e-8
ISSUE_FEE_RATE = 0.1
ELEMENTS_RPC_PRECISION = 8

# some random cosigner xpubs
SEEDS = [bytes([i]*32) for i in range(1,5)]
COSIGNERS = [bip32.HDKey.from_seed(seed, version=NET["xprv"]) for seed in SEEDS]

# uncomment more lines to add more sighashes
BASIC_SIGHASHES = [SIGHASH.ALL, SIGHASH.NONE, SIGHASH.SINGLE]
ALL_SIGHASHES = BASIC_SIGHASHES
ALL_SIGHASHES = ALL_SIGHASHES + [sh | SIGHASH.ANYONECANPAY for sh in BASIC_SIGHASHES]
ALL_SIGHASHES = ALL_SIGHASHES + [sh | SIGHASH.RANGEPROOF for sh in BASIC_SIGHASHES]
ALL_SIGHASHES = ALL_SIGHASHES + [sh | SIGHASH.ANYONECANPAY | SIGHASH.RANGEPROOF for sh in BASIC_SIGHASHES]

def sighash_to_str(sh: int) -> str:
    if sh is None or sh == -1:
        return "DEFAULT"

    base = sh & ~(SIGHASH.ANYONECANPAY|SIGHASH.RANGEPROOF)
    base_str = {
        SIGHASH.DEFAULT: "DEFAULT",
        SIGHASH.ALL: "ALL",
        SIGHASH.NONE: "NONE",
        SIGHASH.SINGLE: "SINGLE"
    }

    try:
        res = base_str[base]
    except KeyError:
        raise ValueError("invalid SIGHASH flags")

    if sh & SIGHASH.ANYONECANPAY:
        res += "|ANYONECANPAY"
    if sh & SIGHASH.RANGEPROOF:
        res += "|RANGEPROOF"

    return res

def sign_psbt(wallet_rpc, psbt:str, sighash=None):
    """Replace with your tested functionality"""
    sighash_str = sighash_to_str(sighash) if sighash is not None else "DEFAULT"
    signed_psbt = wallet_rpc.walletprocesspsbt(psbt, True, sighash_str)['psbt']
    return signed_psbt

def sign_psbt_embit(psbt:str, root=ROOTKEY):
    """Replace with your tested functionality"""
    psbt = PSET.from_string(psbt)
    psbt.sign_with(root, sighash=None) # tell embit to sign with whatever sighash is provided
    return str(psbt)

############

def random_wallet_name():
    return "test"+random.randint(0,0xFFFFFFFF).to_bytes(4,'big').hex()

def create_wallet(erpc, d1, d2, mbk=MBK):
    wname = random_wallet_name()
    # to derive addresses
    desc1 = Descriptor.from_string(d1)
    desc2 = Descriptor.from_string(d2)
    # to add checksums
    d1 = add_checksum(str(d1))
    d2 = add_checksum(str(d2))
    erpc.createwallet(wname, False, True, "", False, True, False)
    w = erpc.wallet(wname)
    res = w.importdescriptors([{
            "desc": d1,
            "active": True,
            "internal": False,
            "timestamp": "now",
            "range": 20,
        },{
            "desc": d2,
            "active": True,
            "internal": True,
            "timestamp": "now",
            "range": 20,
        }])
    assert all([k["success"] for k in res])
    w.importmasterblindingkey(mbk.secret.hex())
    # detect addr type as Bitcoin Core is stupid
    if desc1.is_wrapped:
        w.addr_type = "p2sh-segwit"
    elif desc1.is_legacy:
        w.addr_type = "legacy"
    else:
        w.addr_type = "bech32"
    return w

def get_assetid(w):
    """
    Returns assetid of a non-bitcoin asset present in the wallet with maximal balance,
    or None if there are no assets in the wallet
    """
    b = w.getbalance()
    if "bitcoin" in b:
        b.pop("bitcoin")
    if not b: # no assets
        return None
    # convert to tuple (assetid, value) and sort by value desc
    assets = sorted([(a, v) for a, v in b.items()], key=lambda x: -x[1])
    # return assetid
    return assets[0][0]

def fund_wallet(erpc, w, amount=1, confidential=True, asset_amount=0):
    """
    Sends `amount` to the wallet `w` and mines this transaction.
    Set confidential=False to make unblinded transaction.
    Set asset_amount if you also want to get a non-bitcoin asset.
    """
    addr_type = w.addr_type
    if confidential and addr_type in ["bech32", "bech32m"]:
        addr_type = "blech32"

    addr = w.getnewaddress("", addr_type)
    if not confidential:
        addr = w.getaddressinfo(addr)["unconfidential"]

    wdefault = erpc.wallet()
    # send asset
    if asset_amount > 0:
        assetid = get_assetid(wdefault)
        wdefault.sendtoaddress(addr, asset_amount, "", "", False, False, 6, "unset", False, assetid)
    # send bitcoin
    if amount > 0:
        wdefault.sendtoaddress(addr, amount)
    wdefault.mine(1)

def inject_sighash(psbt, sighash):
    psbt = PSET.from_string(psbt)
    for inp in psbt.inputs:
        inp.sighash_type = sighash
    return str(psbt)

def issue(erpc, w, name, asset_amount, domain, ticker=None, precision=0, token_amount=0, asset_address=None, token_address=None, pubkey=None, collection="", blind=True):
    asset_address = asset_address or w.getnewaddress()
    # TODO: pubkey should be from utxo instead
    pubkey = pubkey or w.getaddressinfo(asset_address).get("pubkey") or w.getaddressinfo(w.getnewaddress())["pubkey"]
    token_address = token_address or w.getnewaddress()

    contract = (
        f'{{' +
        (f'"collection":"{collection}",' if collection else "") +
        f'"entity":{{"domain":"{domain}"}},"issuer_pubkey":"{pubkey}","name":"{name}","precision":{precision},' +
        (f'"ticker":"{ticker}",' if ticker else "") +
        f'"version":{CONTRACT_VERSION}}}'
    )

    contract_hash = hashlib.sha256(contract.encode()).digest()

    LBTC = w.dumpassetlabels()["bitcoin"]
    # unspent LBTC outputs
    utxos = [utxo for utxo in w.listunspent(1, 9999999, [], True, {"asset": LBTC})]
    if not utxos:
        raise RuntimeError(f"Not enough funds. Send some LBTC to {w.getnewaddress()}.")

    utxos.sort(key=lambda utxo: -utxo["amount"])
    utxo = utxos[0]
    fee = ISSUE_FEE
    # run twice - with base fee and then with real fee
    for _ in range(2):
        rawtx = w.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{ w.getrawchangeaddress(): round(utxo["amount"]-fee, 8)}, {"fee": fee}]
        )
        issueconf = {
            "asset_amount": asset_amount,
            "asset_address": asset_address,
            "blind": blind,
            "contract_hash": contract_hash[::-1].hex(),
        }
        if token_amount != 0:
            issueconf.update({
                "token_amount": token_amount,
                "token_address": token_address,
            })

        rawissue = w.rawissueasset(rawtx, [issueconf])[0]
        hextx = rawissue.pop("hex")
        blinded = w.blindrawtransaction(hextx, True, [], blind)
        finalized = w.signrawtransactionwithwallet(blinded)["hex"]
        mempooltest = w.testmempoolaccept([finalized])[0]
        if not mempooltest["allowed"]:
            raise RuntimeError(f"Tx can't be broadcasted: {mempooltest['reject-reason']}")
        vsize = mempooltest["vsize"]
        fee = round(math.ceil(vsize*ISSUE_FEE_RATE)*1e-8, 8)

    erpc.sendrawtransaction(finalized)
    w.mine(1)
    assetid = rawissue["asset"]
    assert assetid in w.getbalance()

    asset = {
        'tag': assetid,
        'contract': contract,
        'prevout_txid': utxo["txid"],
        'prevout_index': utxo["vout"]
    }
    return asset

def create_psbt(erpc, w, amount=0.1, destination=None, confidential=True, confidential_change=True, sighash=None, asset=None):
    wdefault = erpc.wallet()
    if not destination:
        destination = wdefault.getnewaddress()
    change = w.getrawchangeaddress(w.addr_type)

    destination_info = OrderedDict({
        "confidential": destination,
        "unconfidential": w.getaddressinfo(destination)["unconfidential"],
    })

    if not confidential:
        destination = w.getaddressinfo(destination)["unconfidential"]
    if not confidential_change:
        change = w.getaddressinfo(change)["unconfidential"]
    outputs = [{destination: amount}]
    options = {
        "includeWatching": True,
        "changeAddress": change,
        "fee_rate": 1,
        "include_explicit": True
    }
    if asset is not None:
        outputs[0]["asset"] = asset
        # if we are sending non-btc asset we need two change addresses - for btc and for asset,
        # and AFAIK there is no way to provide that to the RPC,
        # so here we will always have confidential change unless we patch psbt afterwards
        options.pop("changeAddress")
        options["change_type"] = w.addr_type
    psbt = w.walletcreatefundedpsbt([], outputs, 0, options, True)
    unblinded = psbt["psbt"]
    try:
        blinded = w.blindpsbt(unblinded)
    except:
        try:
            blinded = w.walletprocesspsbt(unblinded, False)['psbt']
        except:
            blinded = None
    # inject sighash for all inputs
    if sighash is not None:
        unblinded = inject_sighash(unblinded, sighash)
        if blinded:
            blinded = inject_sighash(blinded, sighash)
    return (
        unblinded, blinded, OrderedDict({
            "destination_address": destination_info,
            "amount": int(10**ELEMENTS_RPC_PRECISION * amount + 0.1),
            "fee": int(10**ELEMENTS_RPC_PRECISION * psbt["fee"] + 0.1)
        })
    )

def check_psbt(erpc, unsigned, signed, sighash=None):
    if sighash:
        psbt = PSET.from_string(signed)
        for inp in psbt.inputs:
            for sig in inp.partial_sigs.values():
                assert sig[-1] == sighash
    combined = erpc.combinepsbt([unsigned, signed])
    final = erpc.finalizepsbt(combined)
    if final["complete"]:
        raw = final["hex"]
    else: # finalize in elements is buggy, may not finalize
        tx = finalize_psbt(PSET.from_string(combined))
        assert tx is not None
        raw = str(tx)
    # test accept
    assert erpc.testmempoolaccept([raw])[0]["allowed"]

def sighash_from_signed_pset(signed: str) -> int:
    sighash = -1
    psbt = PSET.from_string(signed)
    for inp in psbt.inputs:
        for sig in inp.partial_sigs.values():
            if sighash < 0:
                sighash = sig[-1]
            else:
                assert sig[-1] == sighash
        if inp.final_scriptwitness:
            sig_items = inp.final_scriptwitness.items
            sig = sig_items[0] if sig_items[0] else sig_items[1]
            if sig:
                if sighash < 0:
                    sighash = sig[-1]
                else:
                    assert sig[-1] == sighash
    return sighash

def get_signatures(signed_pset: str) -> dict:
    psbt = PSET.from_string(signed_pset)
    sigs = OrderedDict()

    for inp_idx, inp in enumerate(psbt.inputs):
        sigs[inp_idx] = OrderedDict()
        if inp.partial_sigs:
            sigs[inp_idx]['partial_sigs'] = [sig.hex() for sig in inp.partial_sigs.values()]
        if inp.final_scriptwitness:
            sigs[inp_idx]['final_scriptwitness'] = [item.hex() for item in inp.final_scriptwitness.items]
        if inp.final_scriptsig:
            sigs[inp_idx]['final_scriptsig'] = inp.final_scriptsig.data.hex()

    return sigs

def get_asset_name(asset: str, metadata_list: list = []) -> str:
    for meta in metadata_list:
        if meta['tag'] == asset:
            contract_obj = json.loads(meta['contract'])
            return "'" + contract_obj['name'] + "' (" + asset[:8] + "...)"

    return "Bitcoin" if asset is None else "'" + asset[:8] + "...'"

def add_asset_metadata(pset_str: str, metadata_list: list) -> str:
    pset = PSET.from_string(pset_str)

    for meta in metadata_list:
        coded_meta = (
            compact.to_bytes(len(meta['contract'])) +
            meta['contract'].encode() +
            bytes.fromhex(meta['prevout_txid'])[::-1] +
            int(meta['prevout_index']).to_bytes(4,'little')
        )
        key = PSBT_ELEMENTS_HWW_GLOBAL_ASSET_METADATA + bytes.fromhex(meta['tag'])[::-1]
        pset.unknown[key] = coded_meta

    return pset.to_string()

def issue_test_assets(erpc, w) -> list:
    return [
        issue(
            erpc,
            w,
            name="Testcoin",
            domain="example.com",
            asset_amount=1.234,
            ticker="TEST",
            precision=2,
            asset_address=w.getnewaddress("", w.addr_type),
            blind=False
        ),
        issue(
            erpc,
            w,
            name="Testcoin2",
            domain="example.com",
            asset_amount=2.345,
            ticker="TEST2",
            precision=4,
            asset_address=w.getnewaddress("", w.addr_type),
            blind=False
        ),
    ]

def bulk_check(erpc, descriptors, collector, mode: str = 'all'):
    w = create_wallet(erpc, *descriptors)
    fund_wallet(erpc, w, 10, confidential=True, asset_amount=10)

    if mode in ['asset_metadata', 'asset_metadata_no_ticker', 'all']:
        # issue our test assets and obtain metadata
        if mode == 'asset_metadata_no_ticker':
            issued_list = [issue(
                erpc,
                w,
                name="Testcoin no ticker",
                domain="example.com",
                asset_amount=1.234,
                precision=2,
                asset_address=w.getnewaddress("", w.addr_type),
                blind=False
            )]
        else:
            issued_list = issue_test_assets(erpc, w)
        issued_dict = { a['tag'] : a for a in issued_list }
        # iterate over issued assets
        assets = [a['tag'] for a in issued_list]
        for asset in assets:
            unblinded, blinded, tx_prop = create_psbt(erpc, w, amount=0.12345678, asset=asset)
            # blinding may fail if all inputs and outputs are confidential, so fund_wallet will return None in blinded
            unsigned = blinded or unblinded
            if asset in issued_dict:
                unsigned = add_asset_metadata(unsigned, issued_list)
                pass
            signed = sign_psbt(w, unsigned)
            check_psbt(erpc, unsigned, signed)
            sh = sighash_from_signed_pset(signed)
            collector.add_test(
                pset=unsigned,
                signatures=get_signatures(signed),
                sighash=sh,
                description=f"Confidential: both, sighash: {sighash_to_str(sh)}, asset: {get_asset_name(asset, issued_list)}",
                **tx_prop,
                asset_contract=issued_dict[asset]['contract'] if asset in issued_dict else None,
                asset_tag=asset
            )

    if mode in ['asset', 'unknown_asset', 'all']:
        # iterate over assets: [some random asset, bitcoin]
        # None for Bitcoin (default asset)
        assets = [get_assetid(w)] if mode == 'unknown_asset' else [get_assetid(w), None]

        for asset in assets:
            unblinded, blinded, tx_prop = create_psbt(erpc, w, amount=0.12345678, asset=asset)
            # blinding may fail if all inputs and outputs are confidential, so fund_wallet will return None in blinded
            unsigned = blinded or unblinded
            signed = sign_psbt(w, unsigned)
            check_psbt(erpc, unsigned, signed)
            sh = sighash_from_signed_pset(signed)
            collector.add_test(
                pset=unsigned,
                signatures=get_signatures(signed),
                sighash=sh,
                description=f"Confidential: both, sighash: {sighash_to_str(sh)}, asset: {get_asset_name(asset)}",
                **tx_prop,
                asset_tag=asset
            )

    if mode in ['sighashes', 'all']:
        for sh in ALL_SIGHASHES:
            unblinded, blinded, tx_prop = create_psbt(erpc, w, sighash=sh)
            # blinding may fail if all inputs and outputs are confidential, so fund_wallet will return None in blinded
            unsigned = blinded or unblinded
            signed = sign_psbt(w, unsigned, sighash=sh)
            check_psbt(erpc, unsigned, signed, sighash=sh)
            collector.add_test(
                pset=unsigned,
                signatures=get_signatures(signed),
                sighash=sh,
                description=f"Confidential: both, sighash: {sighash_to_str(sh)}",
                **tx_prop
            )

    # test all confidential-unconfidential pairs
    conf_status = {
        (False, False): "none",
        (True, False): "input",
        (False, True): "output",
        (True, True): "both"
    }
    if mode in ['blinded_unblinded', 'all']:
        for conf_input in [True, False]:
            w = create_wallet(erpc, *descriptors)
            fund_wallet(erpc, w, 10, confidential=conf_input)
            for conf_destination in [True, False]:
                unblinded, blinded, tx_prop = create_psbt(erpc, w, confidential=conf_destination)
                # blinding may fail if all inputs and outputs are confidential, so fund_wallet will return None in blinded
                unsigned = blinded or unblinded
                signed = sign_psbt(w, unsigned)
                check_psbt(erpc, unsigned, signed)
                sh = sighash_from_signed_pset(signed)
                collector.add_test(
                    pset=unsigned,
                    signatures=get_signatures(signed),
                    sighash=sh,
                    description=(f"Confidential: {conf_status[(conf_input, conf_destination)]}, "
                                f"sighash: {sighash_to_str(sh)}"),
                    **tx_prop
                )

def derivation_quote(path: str) -> str:
    return path.replace("h", "'")

##########################


@pytest.mark.parametrize("mode", ['sighashes', 'blinded_unblinded', 'asset', 'asset_metadata'])
def test_wpkh(erpc, collector, mode, description="Single signature P2WPKH"):
    derivation = "84h/1h/0h"
    xprv = ROOTKEY.derive(f"m/{derivation}")
    xpub = xprv.to_public()
    # change and receive descriptors
    descriptors = (
        f"wpkh([{FGP}/{derivation}]{xprv}/0/*)",
        f"wpkh([{FGP}/{derivation}]{xprv}/1/*)"
    )

    collector.define_suite(
        kind="valid",
        name="wpkh",
        mbk=MBK_SLIP77,
        policy_map="wpkh(@0)",
        keys_info=[f"[{FGP}/{derivation_quote(derivation)}]{xpub}/**"],
        description=description
    )
    bulk_check(erpc, descriptors, collector, mode)

@pytest.mark.parametrize("mode", ['sighashes', 'blinded_unblinded', 'asset'])
def test_sh_wpkh(erpc, collector, mode):
    derivation = "49h/1h/0h"
    xprv = ROOTKEY.derive(f"m/{derivation}")
    xpub = xprv.to_public()
    # change and receive descriptors
    descriptors = (
        f"sh(wpkh([{FGP}/{derivation}]{xprv}/0/*))",
        f"sh(wpkh([{FGP}/{derivation}]{xprv}/1/*))"
    )
    collector.define_suite(
        kind="valid",
        name="sh_wpkh",
        mbk=MBK_SLIP77,
        policy_map="sh(wpkh(@0))",
        keys_info=[f"[{FGP}/{derivation_quote(derivation)}]{xpub}/**"],
        description="Single signature P2SH-P2WPKH"
    )
    bulk_check(erpc, descriptors, collector, mode)

@pytest.mark.parametrize("mode", ['sighashes', 'blinded_unblinded', 'asset'])
def test_pkh(erpc, collector, mode):
    derivation = "44h/1h/0h"
    xprv = ROOTKEY.derive(f"m/{derivation}")
    xpub = xprv.to_public()
    # change and receive descriptors
    descriptors = (
        f"pkh([{FGP}/{derivation}]{xprv}/0/*)",
        f"pkh([{FGP}/{derivation}]{xprv}/1/*)"
    )
    collector.skip_suite() # Legacy transactions are not currently supported
    bulk_check(erpc, descriptors, collector, mode)

@pytest.mark.parametrize("mode", ['sighashes', 'blinded_unblinded', 'asset'])
def test_wsh(erpc, collector, mode):
    # 1-of-2 multisig
    derivation = "48h/1h/0h/2h"
    xprv = ROOTKEY.derive(f"m/{derivation}")
    xpub = xprv.to_public()
    cosigner = COSIGNERS[0].derive(f"m/{derivation}").to_public()
    # change and receive descriptors
    descriptors = (
        f"wsh(sortedmulti(1,[12345678/{derivation}]{cosigner}/0/*,[{FGP}/{derivation}]{xprv}/0/*))",
        f"wsh(sortedmulti(1,[12345678/{derivation}]{cosigner}/1/*,[{FGP}/{derivation}]{xprv}/1/*))"
    )
    collector.define_suite(
        kind="valid",
        name="wsh_sortedmulti",
        mbk=MBK_SLIP77,
        policy_map="wsh(sortedmulti(1,@0,@1))",
        keys_info=[
            f"[12345678/{derivation_quote(derivation)}]{cosigner}/**",
            f"[{FGP}/{derivation_quote(derivation)}]{xpub}/**",
        ],
        description="Multiple signature 1-of-2 P2WSH"
    )
    bulk_check(erpc, descriptors, collector, mode)

@pytest.mark.parametrize("mode", ['sighashes', 'blinded_unblinded', 'asset'])
def test_sh_wsh(erpc, collector, mode):
    # 1-of-2 multisig
    derivation = "48h/1h/0h/1h"
    xprv = ROOTKEY.derive(f"m/{derivation}")
    xpub = xprv.to_public()
    cosigner = COSIGNERS[0].derive(f"m/{derivation}").to_public()
    # change and receive descriptors
    descriptors = (
        f"sh(wsh(sortedmulti(1,[12345678/{derivation}]{cosigner}/0/*,[{FGP}/{derivation}]{xprv}/0/*)))",
        f"sh(wsh(sortedmulti(1,[12345678/{derivation}]{cosigner}/1/*,[{FGP}/{derivation}]{xprv}/1/*)))"
    )
    collector.define_suite(
        kind="valid",
        name="sh_wsh_sortedmulti",
        mbk=MBK_SLIP77,
        policy_map="sh(wsh(sortedmulti(1,@0,@1)))",
        keys_info=[
            f"[12345678/{derivation_quote(derivation)}]{cosigner}/**",
            f"[{FGP}/{derivation_quote(derivation)}]{xpub}/**",
        ],
        description="Multiple signature 1-of-2 P2SH-P2WSH"
    )
    bulk_check(erpc, descriptors, collector, mode)

@pytest.mark.parametrize("mode", ['sighashes', 'blinded_unblinded', 'asset'])
def test_sh(erpc, collector, mode):
    # 1-of-2 multisig
    derivation = "45h"
    xprv = ROOTKEY.derive(f"m/{derivation}")
    xpub = xprv.to_public()
    cosigner = COSIGNERS[0].derive(f"m/{derivation}").to_public()
    # change and receive descriptors
    descriptors = (
        f"sh(sortedmulti(1,[12345678/{derivation}]{cosigner}/0/*,[{FGP}/{derivation}]{xprv}/0/*))",
        f"sh(sortedmulti(1,[12345678/{derivation}]{cosigner}/1/*,[{FGP}/{derivation}]{xprv}/1/*))"
    )
    collector.skip_suite() # Legacy transactions are not currently supported
    bulk_check(erpc, descriptors, collector, mode)


# Execute only if started as 'pytest --target=unknown_asset'
@pytest.mark.target("unknown_asset")
@pytest.mark.parametrize("mode", ['unknown_asset'])
def test_wpkh_unknown_asset(erpc, collector, mode):
    test_wpkh(erpc, collector, mode, description="Unknown asset: single signature P2WPKH")

# Execute only if started as 'pytest --target=asset_metadata'
@pytest.mark.target("asset_metadata")
@pytest.mark.parametrize("mode", ['asset_metadata'])
def test_wpkh_asset_metadata(erpc, collector, mode):
    test_wpkh(erpc, collector, mode, description="Asset metatada: single signature P2WPKH")

# Execute only if started as 'pytest --target=asset_metadata_no_ticker'
@pytest.mark.target("asset_metadata_no_ticker")
@pytest.mark.parametrize("mode", ['asset_metadata_no_ticker'])
def test_wpkh_asset_metadata_no_ticker(erpc, collector, mode):
    test_wpkh(erpc, collector, mode, description="Asset metatada, no ticker: single signature P2WPKH")
