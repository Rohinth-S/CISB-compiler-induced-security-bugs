#include "UndefFreezePass.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Operator.h"
#include "llvm/Support/raw_ostream.h"

#include <vector>
#include <fstream>
#include <cstdlib>

using namespace llvm;

static void logUndefAudit(StringRef FuncName, StringRef Details) {
  const char *LogPath = getenv("CISB_AUDIT_LOG");
  if (!LogPath) return;
  std::ofstream Out(LogPath, std::ios::app);
  if (Out.is_open()) {
    Out << "{\"pass\":\"UndefFreezePass\",\"function\":\"" << FuncName.str()
        << "\",\"details\":\"" << Details.str()
        << "\",\"action\":\"FreezeInst inserted & overflow flags stripped\"}\n";
  }
}

PreservedAnalyses UndefFreezePass::run(Function &F, FunctionAnalysisManager &FAM) {
  bool Modified = false;

  for (BasicBlock &BB : F) {
    auto *BI = dyn_cast<BranchInst>(BB.getTerminator());
    if (!BI || !BI->isConditional()) continue;

    Value *Cond = BI->getCondition();
    if (!Cond) continue;

    // Direct undef condition: br i1 undef
    if (isa<UndefValue>(Cond)) {
      IRBuilder<> Builder(BI);
      Value *Frozen = Builder.CreateFreeze(Cond);
      BI->setCondition(Frozen);
      logUndefAudit(F.getName(), "Direct undef branch condition frozen");
      Modified = true;
      continue;
    }

    auto *Cmp = dyn_cast<ICmpInst>(Cond);
    if (!Cmp) continue;

    IRBuilder<> Builder(Cmp);

    for (unsigned i = 0; i < 2; ++i) {
      Value *Op = Cmp->getOperand(i);

      if (isa<UndefValue>(Op)) {
        Value *Frozen = Builder.CreateFreeze(Op);
        Cmp->setOperand(i, Frozen);
        errs() << "[CISB-Guard:UndefFreeze] Frozen undef operand in icmp inside " << F.getName() << "\n";
        logUndefAudit(F.getName(), "Undef operand in ICmpInst frozen");
        Modified = true;
      } else if (auto *BinOp = dyn_cast<BinaryOperator>(Op)) {
        // Check 1-hop feeding binary operator for undef operands
        bool HasUndefOperand = false;
        for (unsigned j = 0; j < 2; ++j) {
          Value *SubOp = BinOp->getOperand(j);
          if (isa<UndefValue>(SubOp)) {
            HasUndefOperand = true;
            IRBuilder<> SubBuilder(BinOp);
            Value *Frozen = SubBuilder.CreateFreeze(SubOp);
            BinOp->setOperand(j, Frozen);
            errs() << "[CISB-Guard:UndefFreeze] Frozen undef in binary op feeding icmp in " << F.getName() << "\n";
            logUndefAudit(F.getName(), "Undef operand in feeding binary op frozen");
            Modified = true;
          }
        }

        // Only strip nsw/nuw if an operand was actually undef
        if (HasUndefOperand) {
          if (auto *OBO = dyn_cast<OverflowingBinaryOperator>(BinOp)) {
            if (OBO->hasNoSignedWrap()) {
              BinOp->setHasNoSignedWrap(false);
            }
            if (OBO->hasNoUnsignedWrap()) {
              BinOp->setHasNoUnsignedWrap(false);
            }
          }
        }
      }
    }
  }

  return Modified ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
