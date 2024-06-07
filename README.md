# testvectors

## Special version for investigation of "unexpected OP_RETURN" issue

This is a special version of the project created to reveal the issue with an unexpected OP_RETURN output in PSET coming after the normal fee output.

To reproduce the issue, please follow these steps:

1. Create any Python 3 environment of your choice and activate it. Something like:

   ```shell
   python -m venv venv
   source venv/bin/activate
   ```

2. Install dependencies:

   ```shell
   pip install -r requirements.txt
   ```

3. Set the environment variable with the path to the Elements daemon:

   ```shell
   export ELEMENTSD_CMD="/path/to/elements/src/elementsd"
   ```

4. Run this specific test enabling built-in debug features:

   ```shell
   export TEST_DEBUG=1
   pytest --target=issue_unexpected_op_return_output
   ```

If all goes well, the result of this test will be the creation of several dump files in the current directory:

- `pset.base64` - resulting PSET in Base64 encoding
- `pset_decoded.json` - resulting PSET decoded to JSON
- `wallet_info.json` - wallet information
- `walletcreatefundedpsbt_out.json` - raw output of `walletcreatefundedpsbt`
- `walletprocesspsbt_out.json` - raw output of `walletprocesspsbt`
- `issue_unexpected_op_return_output.json` - normally test data should be collected here, but for this specific test, it's empty
