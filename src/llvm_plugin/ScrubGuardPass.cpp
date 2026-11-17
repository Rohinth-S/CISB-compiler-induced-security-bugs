#include "ScrubGuardPass.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/CFG.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Analysis/CFG.h"
#include "llvm/Support/raw_ostream.h"

#include <vector>
#include <string>
#include <algorithm>
#include <fstream>
#include <cstdlib>

using namespace llvm;

static bool isSensitiveName(StringRef Name) {
  std::string Lower = Name.lower();
  const char *Keywords[] = {"secret", "key", "pass", "pwd", "hash", "token", "scrub", "wipe", "auth", "priv"};
  for (const char *kw : Keywords) {
    if (Lower.find(kw) != std::string::npos) return true;
  }
  return false;
}

static bool isLifetimeOrDbg(const Instruction *I) {
  if (auto *II = dyn_cast<IntrinsicInst>(I)) {
    switch (II->getIntrinsicID()) {
    case Intrinsic::lifetime_start:
    case Intrinsic::lifetime_end:
    case Intrinsic::dbg_declare:
    case Intrinsic::dbg_value:
    case Intrinsic::dbg_assign:
    case Intrinsic::dbg_label:
      return true;
    default:
      return false;
    }
  }
  return false;
}

static bool instructionReadsOrEscapes(Instruction &I, AllocaInst *AI) {
  if (isLifetimeOrDbg(&I)) return false;

  if (auto *LI = dyn_cast<LoadInst>(&I)) {
    if (getUnderlyingObject(LI->getPointerOperand()) == AI) return true;
  }
  if (auto *SI = dyn_cast<StoreInst>(&I)) {
    if (getUnderlyingObject(SI->getValueOperand()) == AI) return true;
  }
  if (auto *CB = dyn_cast<CallBase>(&I)) {
    for (unsigned i = 0; i < CB->arg_size(); ++i) {
      if (getUnderlyingObject(CB->getArgOperand(i)) == AI) {
        if (!CB->doesNotAccessMemory()) return true;
      }
    }
  }
  if (auto *RI = dyn_cast<ReturnInst>(&I)) {
    if (RI->getReturnValue() && getUnderlyingObject(RI->getReturnValue()) == AI) {
      return true;
    }
  }
  return false;
}

static bool isBufferReadAfter(MemSetInst *MSI, AllocaInst *AI, Function &F) {
  BasicBlock *StartBB = MSI->getParent();
  bool PassedMSI = false;
  for (Instruction &I : *StartBB) {
    if (&I == MSI) {
      PassedMSI = true;
      continue;
    }
    if (PassedMSI) {
      if (instructionReadsOrEscapes(I, AI)) return true;
    }
  }

  std::vector<BasicBlock *> Worklist;
  SmallPtrSet<BasicBlock *, 16> Visited;
  for (BasicBlock *Succ : successors(StartBB)) {
    if (Visited.insert(Succ).second) {
      Worklist.push_back(Succ);
    }
  }

  while (!Worklist.empty()) {
    BasicBlock *BB = Worklist.back();
    Worklist.pop_back();

    for (Instruction &I : *BB) {
      if (instructionReadsOrEscapes(I, AI)) return true;
    }

    for (BasicBlock *Succ : successors(BB)) {
      if (Visited.insert(Succ).second) {
        Worklist.push_back(Succ);
      }
    }
  }
  return false;
}

static void logAudit(StringRef FuncName, StringRef VarName, StringRef Reason) {
  const char *LogPath = getenv("CISB_AUDIT_LOG");
  if (!LogPath) return;
  std::ofstream Out(LogPath, std::ios::app);
  if (Out.is_open()) {
    Out << "{\"pass\":\"ScrubGuardPass\",\"function\":\"" << FuncName.str()
        << "\",\"variable\":\"" << VarName.str()
        << "\",\"reason\":\"" << Reason.str()
        << "\",\"action\":\"Volatile memset + InlineAsm memory barrier inserted\"}\n";
  }
}

PreservedAnalyses ScrubGuardPass::run(Function &F, FunctionAnalysisManager &FAM) {
  bool Modified = false;
  std::vector<MemSetInst *> Targets;

  for (BasicBlock &BB : F) {
    for (Instruction &I : BB) {
      if (auto *MSI = dyn_cast<MemSetInst>(&I)) {
        if (MSI->isVolatile()) continue;

        // Check if value written is constant 0
        auto *ConstVal = dyn_cast<ConstantInt>(MSI->getValue());
        if (!ConstVal || ConstVal->getZExtValue() != 0) continue;

        Value *Dest = MSI->getRawDest();
        Value *Underlying = getUnderlyingObject(Dest);
        auto *AI = dyn_cast<AllocaInst>(Underlying);
        if (!AI) continue;

        bool Sensitive = isSensitiveName(AI->getName());
        bool DeadAfter = !isBufferReadAfter(MSI, AI, F);

        if (Sensitive || DeadAfter) {
          Targets.push_back(MSI);
        }
      }
    }
  }

  for (MemSetInst *MSI : Targets) {
    Value *Dest = MSI->getRawDest();
    Value *Underlying = getUnderlyingObject(Dest);
    AllocaInst *AI = cast<AllocaInst>(Underlying);

    // 1. Mark memset as volatile so LLVM DSE and MemCpyOpt will not eliminate it
    MSI->setVolatile(ConstantInt::getTrue(F.getContext()));

    // 2. Insert inline assembly barrier: asm volatile("" : : "r"(Dest) : "memory");
    // In LLVM 18, opaque pointer Dest has type ptr
    FunctionType *AsmFTy = FunctionType::get(Type::getVoidTy(F.getContext()), {Dest->getType()}, false);
    InlineAsm *IA = InlineAsm::get(AsmFTy, "", "r,~{memory}", /*hasSideEffects=*/true);

    IRBuilder<> Builder(MSI->getNextNode());
    Builder.CreateCall(AsmFTy, IA, {Dest});

    std::string Reason = isSensitiveName(AI->getName()) ? "Sensitive variable identifier" : "Dead-at-exit store elimination threat";
    errs() << "[CISB-Guard:ScrubGuard] Protected zeroing store in " << F.getName() 
           << " (" << AI->getName() << "): " << Reason << "\n";

    logAudit(F.getName(), AI->getName(), Reason);
    Modified = true;
  }

  return Modified ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
