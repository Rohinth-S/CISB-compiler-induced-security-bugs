import unittest
from simulator import CASES,run_case,run_all
class TestSimulator(unittest.TestCase):
 def test_cases(self): self.assertEqual(len(CASES),4)
 def test_baseline(self):
  for c in CASES: self.assertEqual(run_case(c,False)['result']['status'],'VULNERABLE')
 def test_mitigated(self):
  for c in CASES: self.assertEqual(run_case(c,True)['result']['status'],'PROTECTED')
 def test_all(self): self.assertEqual(len(run_all()),4)
if __name__=='__main__': unittest.main()
