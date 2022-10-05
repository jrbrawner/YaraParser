import plyara
import plyara.utils
import yara

class MultiParser:

    parser = plyara.Plyara()
    parsed_rules = {}
    rules_text = list()

    def __init__(self, yara_text):
        self.parser.clear()
        self.parsed_rules = self.parser.parse_string(yara_text)
        self.rules_text.append('wip')

    def get_rules_dict(self):
        counter = 0
        data = {}
        holder = {}

        for i in self.parsed_rules:
            data['rule_name'] = i["rule_name"]
            holder[counter] = data
            counter += 1
        
        return holder