import plyara
import plyara.utils
import yara


class YaraParser:

    parser = plyara.Plyara()

    parsed_rule = {}
    rule_text = ""
    rule_hash = ""
    compiles = ""

    def __init__(self, yara_text, *multiple_rules):
        self.parser.clear()

        if multiple_rules == True:
            self.parsed_rule_list = list()
            self.rule_text_list = list()
            self.parsed_rule_list.append(
                [x for x in self.parser.parse_string(yara_text)]
            )
        else:
            self.parsed_rule = self.parser.parse_string(yara_text)
            self.rule_text = plyara.utils.rebuild_yara_rule(self.parsed_rule[0])

    def get_rule_name(self):
        """Return rule name."""
        return self.parsed_rule[0]["rule_name"]

    def get_rule_meta(self):
        """Return rule meta description."""
        return self.parsed_rule[0]["raw_meta"]

    def get_rule_strings_kvp(self):
        """Return rule strings as kvp."""
        return self.parsed_rule[0]["strings"]

    def get_rule_strings(self):
        """Return rule raw strings."""
        return self.parsed_rule[0]["raw_strings"]

    def get_rule_conditions(self):
        """Return rule conditions."""
        return self.parsed_rule[0]["raw_condition"]

    def get_logic_hash(self):
        """Return SHA-256 hash of rule strings and conditions."""
        if self.rule_hash == "":
            self.rule_hash = plyara.utils.generate_logic_hash(self.parsed_rule[0])
            return self.rule_hash
        return self.rule_hash

    def try_compile(self):
        """Attempts to compile provided rule. Returns True if rule compiles, returns False with the error message if the rule does not compile."""
        if self.compiles == "":
            try:
                result = yara.compile(source=self.rule_text)
                self.compiles = "True"
                return self.compiles
            except yara.YaraSyntaxError as e:
                self.compiles = "False " + str(e)
                return self.compiles
