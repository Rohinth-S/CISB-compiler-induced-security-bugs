#include "CFGVerifyPass.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/Support/raw_ostream.h"

#include <vector>
#include <fstream>
#include <set>
#include <map>
#include <cstdlib>

using namespace llvm;

static bool isFailureBlock(const BasicBlock &BB) {
  for (const Instruction &I : BB) {
    if (auto *CB = dyn_cast<CallBase>(&I)) {
      if (Function *Callee = CB->getCalledFunction()) {
        StringRef N = Callee->getName();
        if (N.contains("abort") || N.contains("exit") || N.contains("panic") ||
            N.contains("assert") || N.contains("ereport") || N.contains("fail") ||
            N.contains("fault") || N.contains("error")) {
          return true;
        }
      }
    }
    if (auto *SI = dyn_cast<StoreInst>(&I)) {
      if (auto *CI = dyn_cast<ConstantInt>(SI->getValueOperand())) {
        if (CI->isNegative()) return true; // e.g. store -1 to %retval in unoptimized IR
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

static bool mustFail(BasicBlock *BB, const std::set<BasicBlock *> &FailBlocks, const PostDominatorTree &PDT) {
  if (FailBlocks.count(BB)) return true;
  for (BasicBlock *FB : FailBlocks) {
    if (PDT.dominates(FB, BB)) return true;
  }
  return false;
}

static unsigned getCheckIDFromMD(MDNode *MD) {
  if (!MD || MD->getNumOperands() == 0) return 0;
  if (auto *CMD = dyn_cast<ConstantAsMetadata>(MD->getOperand(0))) {
    if (auto *CI = dyn_cast<ConstantInt>(CMD->getValue())) {
      return CI->getZExtValue();
    }
  }
  return 0;
}

static MDNode *createCheckMD(LLVMContext &Ctx, unsigned CheckID, StringRef Tag) {
  Metadata *Elts[] = {
    ConstantAsMetadata::get(ConstantInt::get(Type::getInt32Ty(Ctx), CheckID)),
    MDString::get(Ctx, Tag)
  };
  return MDNode::get(Ctx, Elts);
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
    DominatorTree &DT = FAM.getResult<DominatorTreeAnalysis>(F);
    PostDominatorTree &PDT = FAM.getResult<PostDominatorTreeAnalysis>(F);

    std::set<BasicBlock *> FailBlocks;
    for (BasicBlock &BB : F) {
      if (isFailureBlock(BB)) {
        FailBlocks.insert(&BB);
      }
    }

    if (FailBlocks.empty()) return PreservedAnalyses::all();

    unsigned TaggedChecks = 0;
    unsigned TaggedOps = 0;
    SmallVector<Metadata *, 8> ExpectedChecks;

    for (BasicBlock &BB : F) {
      auto *BI = dyn_cast<BranchInst>(BB.getTerminator());
      if (!BI || !BI->isConditional()) continue;

      BasicBlock *BT = BI->getSuccessor(0);
      BasicBlock *BF = BI->getSuccessor(1);

      bool TrueFails = mustFail(BT, FailBlocks, PDT);
      bool FalseFails = mustFail(BF, FailBlocks, PDT);

      // XOR post-dominance check: MustFail(BT) ^ MustFail(BF)
      if (TrueFails ^ FalseFails) {
        TaggedChecks++;
        unsigned CheckID = TaggedChecks;

        MDNode *SecMD = createCheckMD(Ctx, CheckID, "security_guard");
        BI->setMetadata("cisb.seccheck", SecMD);
        ExpectedChecks.push_back(ConstantAsMetadata::get(ConstantInt::get(Type::getInt32Ty(Ctx), CheckID)));

        BasicBlock *SafeTarget = TrueFails ? BF : BT;
        // Tag potentially hazardous operations dominated by this security check
        for (BasicBlock &TargetBB : F) {
          if (DT.dominates(SafeTarget, &TargetBB)) {
            for (Instruction &I : TargetBB) {
              if (I.getOpcode() == Instruction::SDiv || I.getOpcode() == Instruction::UDiv ||
                  I.getOpcode() == Instruction::SRem || I.getOpcode() == Instruction::URem) {
                MDNode *GuardMD = createCheckMD(Ctx, CheckID, "guarded_op");
                I.setMetadata("cisb.guarded_by", GuardMD);
                TaggedOps++;
              }
            }
          }
        }
      }
    }

    if (TaggedChecks > 0) {
      F.setMetadata("cisb.expected_checks", MDNode::get(Ctx, ExpectedChecks));
      errs() << "[CISB-Guard:CFGVerify] Pre-Opt tagged " << TaggedChecks 
             << " security check(s) and " << TaggedOps << " guarded op(s) in " << F.getName() << "\n";
      logCFGAudit(F.getName(), "Pre-Opt", "Tagged security check branches", TaggedChecks, TaggedOps);
    }
    return PreservedAnalyses::all();
  } else {
    // POST-OPTIMIZATION PASS: Verify checks survived and remain dominating
    DominatorTree &DT = FAM.getResult<DominatorTreeAnalysis>(F);

    std::map<unsigned, Instruction *> SurvivedChecks;
    std::vector<std::pair<unsigned, Instruction *>> GuardedOps;

    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        if (MDNode *MD = I.getMetadata("cisb.seccheck")) {
          unsigned CID = getCheckIDFromMD(MD);
          if (CID > 0) SurvivedChecks[CID] = &I;
        }
        if (MDNode *MD = I.getMetadata("cisb.guarded_by")) {
          unsigned CID = getCheckIDFromMD(MD);
          if (CID > 0) GuardedOps.push_back({CID, &I});
        }
      }
    }

    bool HasErasure = false;
    bool HasReordering = false;

    // 1. Check for Erased Checks
    if (MDNode *ExpectedMD = F.getMetadata("cisb.expected_checks")) {
      for (unsigned i = 0; i < ExpectedMD->getNumOperands(); ++i) {
        if (auto *CMD = dyn_cast<ConstantAsMetadata>(ExpectedMD->getOperand(i))) {
          if (auto *CI = dyn_cast<ConstantInt>(CMD->getValue())) {
            unsigned ExpectedID = CI->getZExtValue();
            if (!SurvivedChecks.count(ExpectedID)) {
              errs() << "[CISB-Guard:CFGVerify] ALERT: Security check ID " << ExpectedID 
                     << " was ERASED by compiler optimization in " << F.getName() << "!\n";
              HasErasure = true;
            }
          }
        }
      }
    }

    for (auto &G : GuardedOps) {
      unsigned CID = G.first;
      if (!SurvivedChecks.count(CID)) {
        errs() << "[CISB-Guard:CFGVerify] ALERT: Guarded operation in " << F.getName() 
               << " lost security check ID " << CID << " (CHECK_ERASED)!\n";
        HasErasure = true;
      }
    }

    // 2. Check for Reordering
    for (auto &G : GuardedOps) {
      unsigned CID = G.first;
      Instruction *GuardedInst = G.second;
      if (SurvivedChecks.count(CID)) {
        Instruction *CheckInst = SurvivedChecks[CID];
        if (!DT.dominates(CheckInst, GuardedInst)) {
          errs() << "[CISB-Guard:CFGVerify] ALERT: Guarded operation in " << F.getName() 
                 << " was hoisted/reordered above check ID " << CID << " (CHECK_REORDERED)!\n";
          HasReordering = true;
        }
      }
    }

    if (HasErasure) {
      logCFGAudit(F.getName(), "Post-Opt", "CHECK_ERASED", SurvivedChecks.size(), GuardedOps.size());
    } else if (HasReordering) {
      logCFGAudit(F.getName(), "Post-Opt", "CHECK_REORDERED", SurvivedChecks.size(), GuardedOps.size());
    } else if (!SurvivedChecks.empty() || !GuardedOps.empty()) {
      errs() << "[CISB-Guard:CFGVerify] Post-Opt verification: " << SurvivedChecks.size() 
             << " security check(s) active, " << GuardedOps.size() << " guarded op(s) verified in " << F.getName() << "\n";
      logCFGAudit(F.getName(), "Post-Opt", "CHECK_VERIFIED", SurvivedChecks.size(), GuardedOps.size());
    }

    return PreservedAnalyses::all();
  }
}
