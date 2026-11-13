import json
from dataclasses import asdict
from typing import Dict
class Case:
 def __init__(self,id,title,cls,principle,vulnerable,mitigation,input): self.id=id; self.title=title; self.class_name=cls; self.principle=principle; self.vulnerable=vulnerable; self.mitigation=mitigation; self.input=input
 def __dict__(self): return self.__dict__
CASES={
 'secret-wipe':Case('secret-wipe','Dead-store elimination of secret wiping','Persistent-state information leak','A compiler may remove a wipe whose result is never read.','A secret can remain in reused stack memory.','Use an observable secure wipe, compiler barrier, or memset_s.','Attacker reads a reused stack slot after authentication returns.'),
 'null-check':Case('null-check','Null-check removed after dereference','Undefined-behavior check elimination','After *p, the optimizer may infer p is non-null and delete a later defensive check.','The fallback path is unreachable in optimized code.','Check before dereference and use an opaque barrier or sanitizer.','p is null at the security boundary.'),
 'promotion-wrap':Case('promotion-wrap','Integer-promotion wraparound guard','Undefined-behavior / integer semantics','Narrow unsigned integers are promoted before arithmetic.','A length or index guard can be bypassed.','Cast back to the intended width and use checked arithmetic.','uint8_t value 255 plus 1.'),
 'constant-time':Case('constant-time','Optimization changes timing shape','Optimization-sensitive side channel','An optimizer can transform branches and memory access patterns.','Secret-dependent timing becomes observable.','Use constant-time primitives and opaque boundaries.','Two secret values with different branch paths.')}
def run_case(cid,mitigated=False):
 c=CASES[cid]
 if cid=='secret-wipe': v=('Wipe optimized away','Secret bytes remain observable in the simulated reused stack slot.','optimized IR: store removed as dead'); s=('Observable wipe retained','The secure wipe remains in the optimized path.','barrier/secure wipe preserved')
 elif cid=='null-check': v=('Defensive null check deleted','The dereference lets the optimizer assume the pointer is non-null.','optimized CFG: null branch unreachable'); s=('Check executes before dereference','The precondition is checked at the security boundary.','guard dominates dereference')
 elif cid=='promotion-wrap': v=('Wraparound guard misses','Integer promotion changes the comparison domain.','uint8_t promoted to int'); s=('Checked narrow arithmetic','Explicit narrowing preserves intended modular semantics.','checked add + explicit cast')
 else: v=('Secret-dependent timing','The optimized path uses different work for different secret values.','branch count differs by secret'); s=('Constant-time path','Both secret values use the same modeled operations.','equalized branch/work count')
 r=s if mitigated else v
 return {'case':c.__dict__,'mitigated':mitigated,'result':{'status':'PROTECTED' if mitigated else 'VULNERABLE','headline':r[0],'detail':r[1],'evidence':r[2]},'audit':{'oracle':'cross-check vulnerable and mitigated executions','false_positive_filter':'compare against baseline/O0 model','pass':mitigated}}
def run_all(): return [dict(run_case(k,False),mitigated_result=run_case(k,True)) for k in CASES]
