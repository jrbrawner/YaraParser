import pytest
from YaraParser.YaraParser import YaraParser


@pytest.fixture()
def test_rule():
    test_rule = """
    import "pe"
    rule cert_blocklist_05e2e6a4cd09ea54d665b075fe22A256 {
        meta:
            author      = "ReversingLabs"
            source      = "ReversingLabs"
            status      = "RELEASED"
            sharing     = "TLP:WHITE"
            category    = "INFO"
            description = "The digital certificate has leaked."
        condition:
            uint16(0) == 0x5A4D and
            for any i in (0..pe.number_of_signatures): (
                pe.signatures[i].subject contains "*.google.com" and
                pe.signatures[i].serial == "05:e2:e6:a4:cd:09:ea:54:d6:65:b0:75:fe:22:a2:56" and
                1308182400 <= pe.signatures[i].not_after
            )
    }
    """
    
    return test_rule


@pytest.fixture
def single_parser(test_rule):
    return YaraParser(test_rule)
    

def test_single_rule_name(single_parser):
    assert single_parser.get_rule_name() == 'cert_blocklist_05e2e6a4cd09ea54d665b075fe22A256'

def test_single_rule_meta(single_parser):
    rule_meta = """
           meta:
            author      = "ReversingLabs"
            source      = "ReversingLabs"
            status      = "RELEASED"
            sharing     = "TLP:WHITE"
            category    = "INFO"
            description = "The digital certificate has leaked."
            """
    rule_meta = rule_meta.strip()
    assert single_parser.get_rule_meta() == rule_meta