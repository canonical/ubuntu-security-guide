import unittest
import os
import tempfile
import lxml.etree as etree
from tools import generate_tailoring_file

class TestGenerateTailoringFile(unittest.TestCase):
    def setUp(self):
        # Create a minimal XCCDF XML for testing
        self.xml_content = '''
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">
            <Value id="var_test">
                <value selector="default">default_value</value>
                <value selector="custom">custom_value</value>
            </Value>
        </Benchmark>
        '''
        self.doc = etree.fromstring(self.xml_content.encode())
        self.etree_doc = etree.ElementTree(self.doc)

    def test_process_var_default(self):
        result = generate_tailoring_file.process_var(self.etree_doc, 'var_test', 'default')
        self.assertEqual(result, 'default_value')

    def test_process_var_custom(self):
        result = generate_tailoring_file.process_var(self.etree_doc, 'var_test', 'custom')
        self.assertEqual(result, 'custom_value')

    def test_process_var_missing(self):
        with self.assertRaises(Exception):
            generate_tailoring_file.process_var(self.etree_doc, 'var_test', 'missing')

if __name__ == '__main__':
    unittest.main()
