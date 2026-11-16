#pragma once

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"

namespace llvm {

class UndefFreezePass : public PassInfoMixin<UndefFreezePass> {
public:
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM);
  static bool isRequired() { return true; }
};

} // namespace llvm
