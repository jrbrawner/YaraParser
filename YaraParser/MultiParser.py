import plyara
import plyara.utils
import yara


class MultiParser:

    parser = plyara.Plyara()
    parsed_rules = {}
    rules_dict = {}
    rule_name_list = list()

    def __init__(self, yara_text):
        self.parser.clear()
        self.parsed_rules = self.parser.parse_string(yara_text)

    def get_rules_dict(self, rule_name_as_key=False):
        """
        Returns a dictionary of each rule containing relevant attributes of the rules, in order of rules parsed.

        rule_name_as_key: Optional parameter to use rule name as the dictionary key, integer number (order rules are parsed) is default.
        """
        if len(self.rules_dict) != 0:
            return self.rules_dict

        counter = 1
        holder = {}

        for i in self.parsed_rules:
            data = {}
            data["rule_name"] = i["rule_name"]
            data["rule_meta"] = i["raw_meta"]
            data["rule_strings"] = i["raw_strings"]
            data["rule_conditions"] = i["raw_condition"]
            data["rule_logic_hash"] = plyara.utils.generate_hash(i)
            data["raw_text"] = plyara.utils.rebuild_yara_rule(i)
            data["compiles"] = self.get_compile_status(data["raw_text"])

            if rule_name_as_key == True:
                holder[data["rule_name"]] = data
            else:
                holder[counter] = data
                counter += 1
        self.rules_dict = holder
        return self.rules_dict

    def get_rule_name_list(self):
        """Get a list of rule names, in order of rules parsed."""

        if len(self.rule_name_list) != 0:
            return self.rule_name_list

        for i in self.parsed_rules:
            self.rule_name_list.append(i["rule_name"])

        return self.rule_name_list

    def get_compile_status(self, rule):
        """Attempts to compile provided rule. Returns True if rule compiles, returns False with the error message if the rule does not compile."""
        try:
            result = yara.compile(source=rule)
            compiles = "True"
            return compiles
        except yara.YaraSyntaxError as e:
            compiles = "False " + str(e)
            return compiles
