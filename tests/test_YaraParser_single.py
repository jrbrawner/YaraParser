import pytest
import re
from YaraParser.SingleParser import SingleParser


@pytest.fixture()
def test_rule_single():
    test_rule_single = """
rule Str_Win32_Winsock2_Library
{
    meta:
        author = "@adricnet"
        description = "Match Winsock 2 API library declaration"
        method = "String match"
        reference = "https://github.com/dfirnotes/rules"
    strings:
        $ws2_lib = "Ws2_32.dll" nocase
        $wsock2_lib = "WSock32.dll" nocase
    condition:
        (any of ($ws2_lib, $wsock2_lib))
}
    """
    
    return test_rule_single

@pytest.fixture
def single_parser(test_rule_single):
    return SingleParser(test_rule_single)
    

def test_single_rule_name(single_parser):
    assert single_parser.get_rule_name() == 'Str_Win32_Winsock2_Library'

def test_single_rule_meta(single_parser):
    test_meta = """
          meta:
            author = "@adricnet"
            description = "Match Winsock 2 API library declaration"
            method = "String match"
            reference = "https://github.com/dfirnotes/rules"
            """
    test_meta = re.sub(r'\s', '', test_meta)
    rule_meta = single_parser.get_rule_meta()
    rule_meta = re.sub(r'\s', '', rule_meta)
    
    assert test_meta == rule_meta

def test_single_rule_strings(single_parser):
    test_strings = """
    strings:
        $ws2_lib = "Ws2_32.dll" nocase
        $wsock2_lib = "WSock32.dll" nocase
    """
    test_strings = re.sub(r'\s', '', test_strings)
    rule_strings = single_parser.get_rule_strings()
    rule_strings = re.sub(r'\s', '', rule_strings)
    
    assert test_strings == rule_strings

def test_single_rule_conditions(single_parser):
    test_condition = """
    condition:
        (any of ($ws2_lib, $wsock2_lib))
    """
    test_condition = re.sub(r'\s', '', test_condition)
    rule_condition = single_parser.get_rule_conditions()
    rule_condition = re.sub(r'\s', '', rule_condition)

    assert test_condition == rule_condition

def test_single_rule_logic_hash(single_parser):
    test_logic_hash = 'fd6a040fff14eeab7e1c367723b121632f746c7599887855ce91b6af04b96be5'
    assert single_parser.get_logic_hash() == test_logic_hash

def test_single_rule_compiles(single_parser):
    assert single_parser.try_compile() == 'True'

def test_single_rule_strings_kvp(single_parser):
    test_strings = """
    [{'name': '$ws2_lib', 'value': 'Ws2_32.dll', 'type': 'text', 'modifiers': ['nocase']}, {'name': '$wsock2_lib', 'value': 'WSock32.dll', 'type': 'text', 'modifiers': ['nocase']}]
    """
    test_strings = re.sub(r'\s', '', test_strings)
    rule_strings = str(single_parser.get_rule_strings_kvp())
    rule_strings = re.sub(r'\s', '', rule_strings)

    assert rule_strings == test_strings
    
    


   
