from email.mime import multipart
import pytest
import re
from YaraParser.MultiParser import MultiParser

@pytest.fixture()
def test_rule_multi():
    test_rule_multi = """
    rule blackhole2_htm10
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "83704d531c9826727016fec285675eb1"
	hash1 = "103ef0314607d28b3c54cd07e954cb25"
	hash2 = "16c002dc45976caae259d7cabc95b2c3"
	hash3 = "fd84d695ac3f2ebfb98d3255b3a4e1de"
	hash4 = "c7b417a4d650c72efebc2c45eefbac2a"
	hash5 = "c3c35e465e316a71abccca296ff6cd22"
	hash2 = "16c002dc45976caae259d7cabc95b2c3"
	hash7 = "10ce7956266bfd98fe310d7568bfc9d0"
	hash8 = "60024caf40f4239d7e796916fb52dc8c"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "</body></html>"
	$string1 = "/icons/back.gif"
	$string2 = ">373K</td><td>"
	$string3 = "/icons/unknown.gif"
	$string4 = ">Last modified</a></th><th><a href"
	$string5 = "tmp.gz"
	$string6 = ">tmp.gz</a></td><td align"
	$string7 = "nbsp;</td><td align"
	$string8 = "</table>"
	$string9 = ">  - </td><td>"
	$string10 = ">filefdc7aaf4a3</a></td><td align"
	$string11 = ">19-Sep-2012 07:06  </td><td align"
	$string12 = "><img src"
	$string13 = "file3fa7bdd7dc"
	$string14 = "  <title>Index of /files</title>"
	$string15 = "0da49e042d"
condition:
	15 of them
}

rule ATM_Malware_XFS_ALICE {
	meta:
		description = "Detects ATM Malware ALICE"
		author = "Frank Boldewin (@r3c0nst)"
		reference = "https://twitter.com/r3c0nst/status/1215265889844637696"
		date = "2020-01-09"
		hash1 = "6b2fac8331e4b3e108aa829b297347f686ade233b24d94d881dc4eff81b9eb30"
		
	strings:
		$String1 = "Project Alice" ascii nocase
		$String2 = "Can't dispense requested amount." ascii nocase
		$String3 = "Selected cassette is unavailable" ascii nocase
		$String4 = "ATM update manager" wide nocase
		$String5 = "Input PIN-code for access" wide nocase
		$String6 = "Supervisor ID" wide nocase
		$Code1 = {50 68 08 07 00 00 6A 00 FF 75 0C FF 75 08 E8} // Get Cash Unit Info
		$Code2 = {50 6A 00 FF 75 10 FF 75 0C FF 75 08 E8} // Dispense Cash
		$Code3 = {68 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 0B C0 75 29 6A} // Check Supervisor ID
		
	condition:
		uint16(0) == 0x5A4D and filesize < 200KB and 4 of ($String*) and all of ($Code*)
}

    """
    return test_rule_multi

@pytest.fixture()
def multi_parser(test_rule_multi):
    return MultiParser(test_rule_multi, strip_whitespace=True)

def test_multi_rule_name(multi_parser: MultiParser):
	multi_parser.get_rules_dict()
	for k,v in multi_parser.rules_dict.items():
		keyword_list = ['author', 'date']
		result = multi_parser.get_meta_fields(v['rule_meta_kvp'], meta_keyword_list=keyword_list)
		print(result)

def test_rule_name_list(multi_parser):
	rule_name_list = multi_parser.get_rule_name_list()
	pass

def test_idk(multi_parser: MultiParser):
	rules = multi_parser.get_rules_dict()
	for k,v in rules.items():
		print(v)
	

