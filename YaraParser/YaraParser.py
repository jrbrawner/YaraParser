import plyara
import plyara.utils
import yara

class YaraParser():

   parser = plyara.Plyara()
   
   parsed_rule = {}
   rule_text = ''
   rule_hash = ''
   compiles = ''

   @classmethod
   def __init__(cls, yara_text):
      cls.parser.clear()
      cls.parsed_rule = cls.parser.parse_string(yara_text)
      cls.rule_text = plyara.utils.rebuild_yara_rule(cls.parsed_rule[0])

   @classmethod
   def get_rule_name(cls):
      """Return rule name."""
      return cls.parsed_rule[0]['rule_name']

   @classmethod
   def get_rule_meta(cls):
      """Return rule meta description."""
      return cls.parsed_rule[0]['metadata']

   @classmethod
   def get_rule_strings_kvp(cls):
      """Return rule strings as kvp."""
      return cls.parsed_rule[0]['strings']

   @classmethod
   def get_rule_strings(cls):
      """Return rule raw strings."""
      return cls.parsed_rule[0]['raw_strings']

   @classmethod
   def get_rule_conditions(cls):
      """Return rule conditions."""
      return cls.parsed_rule[0]['raw_condition']

   @classmethod
   def get_rule_hash(cls):
      if cls.rule_hash == '':
         cls.rule_hash = plyara.utils.generate_logic_hash(cls.parsed_rule[0])
         return cls.rule_hash
      return cls.rule_hash

   @classmethod
   def try_compile(cls):
      """ Takes raw Yara rule text and tries to compile the rule. Returns result of either true, or false. """
      if cls.compiles == '':
         try:
            result = yara.compile(source=cls.rule_text)
            cls.compiles = 'True'
            return cls.compiles
         except yara.YaraSyntaxError as e:
            cls.compiles = 'False ' + str(e)
            return cls.compiles
