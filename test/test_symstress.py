"""
Test cases for the symstress module.
"""

from collections import defaultdict
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile

from pytest import fixture

from symstress.parse.cparse import CParse


@fixture
def lwip_source() -> Path:
    """
    Extract the lwip source to a temporary directory and return the path.
    """
    LWIP_SOURCE_PATH = Path(__file__).with_name("sources") / "lwip-2.1.3.zip"
    with TemporaryDirectory() as td:
        with ZipFile(LWIP_SOURCE_PATH, "r") as zf:
            zf.extractall(td)
            yield (Path(td) / "lwip-2.1.3").resolve()


@fixture
def coreutils_source() -> Path:
    """
    Extract the coreutils source to a temporary directory and return the path.
    """
    LWIP_SOURCE_PATH = Path(__file__).with_name("sources") / "coreutils-master.zip"
    with TemporaryDirectory() as td:
        with ZipFile(LWIP_SOURCE_PATH, "r") as zf:
            zf.extractall(td)
            yield (Path(td) / "coreutils-master").resolve()


def test_lwip_onefile(lwip_source: Path) -> None:
    """
    Test lwip simple string variable.
    """
    source_file = lwip_source / "src" / "netif" / "ppp" / "chap-new.c"
    assert source_file.exists(), f"Source file {source_file} not found."
    parser = CParse()
    parser.parse(source_file)
    strings = parser.map_symbols()
    assert strings == {
        "chap_auth_peer": {
            "CHAP digest 0x%x requested but not available",
            "CHAP: peer authentication already started!",
        },
        "chap_auth_with_peer": {
            "CHAP: authentication with peer already started!",
            "CHAP digest 0x%x requested but not available",
        },
        "chap_verify_response": {"No CHAP secret found for authenticating %q"},
        "chap_respond": {"No CHAP secret found for authenticating us to %q", "%.*v"},
        "chap_handle_status": {
            "%s",
            "CHAP authentication failed",
            "%s: %.*v",
            "CHAP authentication succeeded",
        },
        "chap_protrej": {"CHAP authentication failed due to protocol-reject"},
        "chap_print_pkt": {
            " <",
            " %s",
            " ",
            " %.2x",
            ">, name = ",
            " id=0x%x",
            " code=0x%x",
            "%.2x",
        },
    }


def test_lwip_allfiles(lwip_source: Path) -> None:
    """
    Test lwip simple string variable.
    """
    parser = CParse()
    for source_file in filter(
        lambda p: p.suffix == ".c", (lwip_source / "lwip-2.1.3" / "src").rglob("**/*")
    ):
        assert source_file.exists(), f"Source file {source_file} not found."
        parser.parse(source_file)
        parser.update_mapping()

    assert len(parser.mapping) == 813, "Wrong number of symbols found."
