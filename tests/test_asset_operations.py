import pytest
from typing import OrderedDict
from pyparsing import *
from lwk import *
from util.debug import *
from test_pset import sighash_from_signed_pset, get_signatures, add_asset_metadata, get_fee, get_asset_issuance_outpoint, MNEMONIC

def parse_wpkh_slip77_descriptor(desc):
    """
    Parses descriptor with a format similar to:
    `ct(slip77(0c1164...b4),elwpkh([f5acc2fd/84'/1'/0']tpubDCtK...1P/<0;1>/*))#u6k3x4g3`
    """
    desc = str(desc)
    mbk = Combine(Word('slip77(') + Word(nums + hexnums) + ')')
    pubkey = Word(alphanums + "'[]/<;>*")
    desc_schema = Word('ct(') + mbk("mbk") + ',elwpkh(' + pubkey("pubkey") + rest_of_line
    return desc_schema.search_string(desc)[0].asDict()

# Execute only if started as 'pytest --target=asset_operations'
@pytest.mark.target("asset_operations")
def test_asset_operations(lwknode, collector):

    mnemonic = Mnemonic(MNEMONIC)
    network = Network.regtest_default()
    policy_asset = network.policy_asset()

    signer = Signer(mnemonic, network)
    desc = signer.wpkh_slip77_descriptor()
    desc_parsed = parse_wpkh_slip77_descriptor(desc)

    collector.define_suite(
        kind="valid",
        name="wpkh",
        mbk=desc_parsed['mbk'],
        policy_map="wpkh(@0)",
        keys_info=[desc_parsed['pubkey']],
        description="Asset operations"
    )

    wollet = Wollet(network, desc, datadir=None)
    wollet_address_result = wollet.address(0)
    assert(wollet_address_result.index() == 0)
    wollet_adddress = wollet_address_result.address()

    funded_satoshi = 100000
    txid = lwknode.send_to_address(wollet_address_result.address(), funded_satoshi, asset=None)
    wollet.wait_for_tx(txid, lwknode.electrum_client)

    assert(wollet.balance()[policy_asset] == funded_satoshi)

    contract = Contract(domain = "ciao.it", issuer_pubkey = "0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904", name = "name", precision = 8, ticker = "TTT", version = 0)
    assert(str(contract) == '{"entity":{"domain":"ciao.it"},"issuer_pubkey":"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904","name":"name","precision":8,"ticker":"TTT","version":0}')

    # Issue the asset
    issued_asset = 12345
    reissuance_tokens = 6789
    builder = network.tx_builder()
    builder.issue_asset(issued_asset, wollet_adddress, reissuance_tokens, wollet_adddress, contract)
    unsigned_pset = builder.finish(wollet)
    signed_pset = signer.sign(unsigned_pset)
    finalized_pset = wollet.finalize(signed_pset)
    tx = finalized_pset.extract_tx()
    txid = lwknode.electrum_client.broadcast(tx)

    asset_id = signed_pset.issuance_asset(0)
    token_id = signed_pset.issuance_token(0)

    wollet.wait_for_tx(txid, lwknode.electrum_client)

    assert(wollet.balance()[asset_id] == issued_asset)
    assert(wollet.balance()[token_id] == reissuance_tokens)

    # Add asset metadata to unsigned PSET
    asset_info = {
        'asset_tag': str(asset_id),
        'contract': str(contract),
        'token_tag': str(token_id)
    }
    asset_info.update(get_asset_issuance_outpoint(str(finalized_pset)))
    vector_pset = add_asset_metadata(str(unsigned_pset), [asset_info])

    destination_address0 = wollet.address(0).address()
    collector.add_test(
        pset=vector_pset,
        signatures=get_signatures(str(finalized_pset)),
        sighash=sighash_from_signed_pset(str(finalized_pset)),
        description=f"Asset issue",
        destination_address=OrderedDict({
            "confidential": str(destination_address0),
            "unconfidential": str(destination_address0.to_unconfidential())
        }),
        amount=str(issued_asset),
        fee=get_fee(str(finalized_pset)),
        asset_contract=str(contract),
        asset_tag=str(asset_id)
    )

    # Reissue the asset
    reissue_asset = 98765
    builder = network.tx_builder()
    builder.reissue_asset(asset_id, reissue_asset, None, None)
    unsigned_pset = builder.finish(wollet)
    signed_pset = signer.sign(unsigned_pset)
    finalized_pset = wollet.finalize(signed_pset)
    tx = finalized_pset.extract_tx()
    txid = lwknode.electrum_client.broadcast(tx)

    wollet.wait_for_tx(txid, lwknode.electrum_client)

    assert(wollet.balance()[asset_id] == issued_asset + reissue_asset)

    # Add asset metadata to unsigned PSET
    vector_pset = add_asset_metadata(str(unsigned_pset), [asset_info])

    destination_address1 = wollet.address(1).address()
    collector.add_test(
        pset=vector_pset,
        signatures=get_signatures(str(finalized_pset)),
        sighash=sighash_from_signed_pset(str(finalized_pset)),
        description=f"Asset reissue",
        destination_address=OrderedDict({
            "confidential": str(destination_address1),
            "unconfidential": str(destination_address1.to_unconfidential())
        }),
        amount=str(reissue_asset),
        fee=get_fee(str(finalized_pset)),
        asset_contract=str(contract),
        asset_tag=str(asset_id)
    )

    # Burn the asset
    burn_asset = 34567
    builder = network.tx_builder()
    builder.add_burn(burn_asset, asset_id)
    unsigned_pset = builder.finish(wollet)
    signed_pset = signer.sign(unsigned_pset)
    finalized_pset = wollet.finalize(signed_pset)
    tx = finalized_pset.extract_tx()
    txid = lwknode.electrum_client.broadcast(tx)

    wollet.wait_for_tx(txid, lwknode.electrum_client)

    assert(wollet.balance()[asset_id] == issued_asset + reissue_asset - burn_asset)

    # Add asset metadata to unsigned PSET
    vector_pset = add_asset_metadata(str(unsigned_pset), [asset_info])

    collector.add_test(
        pset=vector_pset,
        signatures=get_signatures(str(finalized_pset)),
        sighash=sighash_from_signed_pset(str(finalized_pset)),
        description=f"Asset burn",
        destination_address={},
        amount=str(burn_asset),
        fee=get_fee(str(finalized_pset)),
        asset_contract=str(contract),
        asset_tag=str(asset_id)
    )
