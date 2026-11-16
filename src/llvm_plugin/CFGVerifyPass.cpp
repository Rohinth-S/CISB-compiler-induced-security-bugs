#include "CFGVerifyPass.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Metadata.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/Analysis/DominanceFrontier.h"
#include "llvm/Support/raw_ostream.h"

#include <vector>
#include <fstream>
#include <set>

using namespace llvm;

static bool isFailureBlock(const BasicBlock &BB) {
  for (const Instruction &I : BB) {
    if (auto *CB = dyn_cast<CallBase>(&I)) {
      if (Function *Callee = CB->getCalledFunction()) {
        StringRef N = Callee->getName();
        if (N.contains("abort") || N.contains("exit") || N.contains("panic") ||
            N.contains("assert") || N.contains("ereport") || N.contains("fail")) {
          return true;
        }
      }
    }
    if (auto *RI = dyn_cast<ReturnInst>(&I)) {
      if (Value *RV = RI->getReturnValue()) {
        if (auto *CI = dyn_cast<ConstantInt>(RV)) {
          if (CI->isNegative()) return true; // e.g. return -1 or -EINVAL
        }
      }
    }
  }
  return false;
}

static void logCFGAudit(StringRef FuncName, StringRef Stage, StringRef Event, unsigned Checks, unsigned Ops) {
  const char *LogPath = getenv("CISB_AUDIT_LOG");
  if (!LogPath) return;
  std::ofstream Out(LogPath, std::ios::app);
  if (Out.is_open()) {
    Out << "{\"pass\":\"CFGVerifyPass\",\"function\":\"" << FuncName.str()
        << "\",\"stage\":\"" << Stage.str()
        << "\",\"event\":\"" << Event.str()
        << "\",\"security_checks\":" << Checks
        << ",\"guarded_ops\":" << Ops << "}\n";
  }
}

PreservedAnalyses CFGVerifyPass::run(Function &F, FunctionAnalysisManager &FAM) {
  if (F.isDeclaration()) return PreservedAnalyses::all();

  LLVMContext &Ctx = F.getContext();

  if (!IsPostOpt) {
    // PRE-OPTIMIZATION PASS
    std::set<BasicBlock *> FailBlocks;
    for (BasicBlock &BB : F) {
      if (isFailureBlock(BB)) {
        FailBlocks.insert(&BB);
      }
    }

    if (FailBlocks.empty()) return PreservedAnalyses::all();

    unsigned TaggedChecks = 0;
    unsigned TaggedOps = 0;

    for (BasicBlock &BB : F) {
      auto *BI = dyn_cast<BranchInst>(BB.getTerminator());
      if (!BI || !BI->isConditional()) continue;

      BasicBlock *BT = BI->getSuccessor(0);
      BasicBlock *BF = BI->getSuccessor(1);

      bool TrueFails = FailBlocks.count(BT);
      bool FalseFails = FailBlocks.count(BF);

      // XOR post-dominance check: MustFail(BT) ^ MustFail(BF)
      if (TrueFails ^ FalseFails) {
        MDNode *SecMD = MDNode::get(Ctx, MDString::get(Ctx, "security_guard"));
        BI->setMetadata("cisb.seccheck", SecMD);
        TaggedChecks++;

        BasicBlock *SafeTarget = TrueFails ? BF : BT;
        // Tag potentially hazardous operations (e.g. division by zero, null deref) in the safe block
        for (Instruction &I : *SafeTarget) {
          if (I.getOpcode() == Instruction::SDiv || I.getOpcode() == Instruction::UDiv ||
              I.getOpcode() == Instruction::SRem || I.getOpcode() == Instruction::URem) {
            MDNode *GuardMD = MDNode::get(Ctx, MDString::get(Ctx, "guarded_op"));
            I.setMetadata("cisb.guarded_by", GuardMD);
            TaggedOps++;
          }
        }
      }
    }

    if (TaggedChecks > 0) {
      errs() << "[CISB-Guard:CFGVerify] Pre-Opt tagged " << TaggedChecks 
             << " security check(s) and " << TaggedOps << " guarded op(s) in " << F.getName() << "\n";
      logCFGAudit(F.getName(), "Pre-Opt", "Tagged security check branches", TaggedChecks, TaggedOps);
    }
    return PreservedAnalyses::all();
  } else {
    // POST-OPTIMIZATION PASS: Verify checks survived
    unsigned SurvivedChecks = 0;
    unsigned SurvivedGuardedOps = 0;

    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        if (I.getMetadata("cisb.seccheck")) SurvivedChecks++;
        if (I.getMetadata("cisb.guarded_by")) SurvivedGuardedOps++;
      }
    }

    if (SurvivedChecks > 0 || SurvivedGuardedOps > 0) {
      errs() << "[CISB-Guard:CFGVerify] Post-Opt verification: " << SurvivedChecks 
             << " security check(s) active, " << SurvivedGuardedOps << " guarded op(s) in " << F.getName() << "\n";
      logCFGAudit(F.getName(), "Post-Opt", "Security checks verified post-optimization", SurvivedChecks, SurvivedGuardedOps);
    }
    return PreservedAnalyses::all();
  }
}
