## Intro
Package I am working on to be used in parsing Yara rules into their individual components. Package may also contain utilities or extra features I develop for working with Yara rules over time.
## Usage

```python
pip install YaraParser
```
## Single Parser
```python
from YaraParser import SingleParser

test = """
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
rule Big_Numbers0
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 20:sized"
		date = "2016-07"
	strings:
		$c0 = /[0-9a-fA-F]{20}/ fullword ascii
	condition:
		$c0
}
"""

parser = SingleParser(test)

parser.get_rule_name()
parser.get_rule_strings()
parser.rule_text
```
```
Big_Numbers0
strings:
                $c0 = /[0-9a-fA-F]{20}/ fullword ascii
rule Big_Numbers0
{
        meta:
                author = "_pusher_"
                description = "Looks for big numbers 20:sized"
                date = "2016-07"

        strings:
                $c0 = /[0-9a-fA-F]{20}/ fullword ascii

        condition:
                $c0
}
```
## MultiParser
```python
from YaraParser import MultiParser

test = """
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
rule Big_Numbers0
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 20:sized"
		date = "2016-07"
	strings:
		$c0 = /[0-9a-fA-F]{20}/ fullword ascii
	condition:
		$c0
}

rule Big_Numbers5
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 256:sized"
		date = "2016-08"
	strings:
        	$c0 = /[0-9a-fA-F]{256}/ fullword wide ascii
	condition:
		$c0
}
"""

parser = MultiParser(test)

rules = parser.get_rules_dict()

for k,v in rules.items():
    v['rule_name']
    v['rule_logic_hash']
    
```
```
Big_Numbers0
cc15c2fe1e9d195ce446c522991f04a9dee858e9752b385473d82c85b5826051
Big_Numbers5
f140e1cdead43088563c392c34604fe8d1f5cb387db78e93049faa91cd4f2941
```
