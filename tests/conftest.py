import subprocess
import psutil
import signal
import pytest
import shutil
import time
import os
import json
from collections import OrderedDict
from util.rpc import BitcoinRPC

DATADIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), "blockchain")
RPCUSER = "liquid"
RPCPASSWORD = "secret"
RPCPORT = 18998
PORT = 18999
ELEMETSD = os.environ.get("ELEMETSD_CMD", default="elemetsd")
CMD = f"{ELEMETSD} -daemon=1 -datadir={DATADIR} -chain=liquidregtest \
        -rpcuser={RPCUSER} -rpcpassword={RPCPASSWORD} -rpcport={RPCPORT} -port={PORT} \
        -fallbackfee=0.0000001 -validatepegin=0 -initialfreecoins=2100000000000000"
PROCESS_NAME="elementsd"
TEST_DATA_FILE = os.environ.get("TEST_DATA_FILE", default="test_data.json")
WAIT_DEBUGGER = os.environ.get("WAIT_DEBUGGER", default="0")
START_NODE = True if int(os.environ.get("START_NODE", default="1")) > 0 else False

def get_coins(rpc):
    # create default wallet if doesn't exist
    if "" not in rpc.listwallets():
        rpc.createwallet("")
    w = rpc.wallet("")
    # get free coins
    w.rescanblockchain()
    w.mine(10)
    balance = w.getbalance()
    addr = w.getnewaddress()
    # send half to our own address to make them confidential
    w.sendtoaddress(addr, balance["bitcoin"]//2)
    w.mine(1)
    # generate some reissueable asset
    w.issueasset(10000, 1)
    w.mine(1)
    assert w.getbalance().get("bitcoin", 0) > 0

def check_node_running(pid = None) -> bool:
    """Check if node is running."""

    active_stats = [psutil.STATUS_RUNNING, psutil.STATUS_SLEEPING]

    if pid is not None:
        try:
            return psutil.Process(pid).status() in active_stats
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return False

    # Iterate over the all the running process
    for proc in psutil.process_iter():
        try:
            # Check if process name contains the given name string.
            if PROCESS_NAME.lower() in proc.name().lower():
                return proc.status() in active_stats
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return False

def start_node() -> int:
    # create datadir for elements
    if os.path.isdir(DATADIR):
        shutil.rmtree(DATADIR)
    os.makedirs(DATADIR)
    # start elementsd
    proc = subprocess.Popen(CMD,
                            stdout=subprocess.PIPE,
                            shell=True, preexec_fn=os.setsid)

    for i in range(100):
        if check_node_running(proc.pid):
            break
        time.sleep(0.2)

    if not check_node_running(proc.pid):
        raise RuntimeError()

    wait_time = int(WAIT_DEBUGGER)
    if wait_time:
        print(f"\nWaiting for debugger ({wait_time} sec)...")
        time.sleep(wait_time)
        print("Starting tests")

    return proc.pid

def stop_node(rpc, pid: int):
    # Send the signal to all the process groups
    for i in range(10):
        try:
            rpc.stop()
        except:
            pass
        time.sleep(1)
        if not check_node_running(pid):
            break

    if check_node_running(pid):
        os.killpg(os.getpgid(pid), signal.SIGTERM)
        time.sleep(3)
        if check_node_running(pid):
            raise RuntimeError()

    # cleanup
    for i in range(100):
        try:
            shutil.rmtree(DATADIR)
            time.sleep(1)
            return
        except Exception as e:
            time.sleep(1)

@pytest.fixture(scope="function", autouse=True)
def erpc():
    """Starts elementsd and gives back rpc instance to work with"""

    daemon_pid = -1
    if START_NODE:
        daemon_pid = start_node()
    else:
        if not check_node_running():
            print("Please start node first with following command line:")
            print(CMD)
            raise RuntimeError()

    try:
        rpc = BitcoinRPC(user=RPCUSER, password=RPCPASSWORD, port=RPCPORT)
        for i in range(100):
            try: # checking if elements is loaded already
                rpc.getblockchaininfo()
                break
            except:
                time.sleep(0.2)
        get_coins(rpc)
        yield rpc
    finally:
        # stop elementsd
        if START_NODE:
            stop_node(rpc, daemon_pid)

class TestDataCollector(object):
    """Collects test tata and dumps it to JSON file"""

    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.data = OrderedDict()
        self.skip = True

    def define_suite(
        self,
        kind: str,
        name: str,
        mbk: str,
        policy_map: str,
        keys_info: list,
        description: str = ""
    ) -> None:
        self.skip = False
        self.kind = kind
        self.suite = name

        if kind not in self.data:
            self.data[kind] = OrderedDict()

        if name in self.data[kind]:
            suite = self.data[kind][name]
            if (
                suite["description"] != description or
                suite["mbk"] != mbk or
                suite["policy_map"] != policy_map or
                suite["keys_info"] != keys_info
            ):
                raise ValueError("unequal parameters for existing test suite")
            return

        self.data[kind][name] = OrderedDict({
            "description": description,
            "mbk": mbk,
            "policy_map": policy_map,
            "keys_info": keys_info,
            "tests": list()
        })

    def skip_suite(self) -> None:
        self.skip = True

    def add_test(
        self,
        pset: str,
        signatures: dict,
        sighash: int = None,
        description: str = ""
    ) -> None:
        if self.skip:
            return

        test = OrderedDict({
            "description": description,
            "pset": pset,
            "signatures": signatures,
            "sighash": sighash
        })

        try:
            self.data[self.kind][self.suite]["tests"].append(test)
        except KeyError:
            raise RuntimeError("test suite not properly defined")

    def dump(self):
        try:
            os.remove(self.filename)
        except OSError:
            pass
        with open(self.filename, "w") as write_file:
            json.dump(self.data, write_file, indent=2)

@pytest.fixture(scope="module", autouse=True)
def collector():
    """Creates and provides test data collector"""

    collector_obj = TestDataCollector(TEST_DATA_FILE)
    yield collector_obj
    collector_obj.dump()
