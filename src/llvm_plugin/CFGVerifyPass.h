#pragma once

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"

namespace llvm {

class CFGVerifyPass : public PassInfoMixin<CFGVerifyPass> {
  bool IsPostOpt;
public:
  explicit CFGVerifyPass(bool IsPostOpt = false) : IsPostOpt(IsPostOpt) {}
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM);
  static bool isRequired() { return true; }
};

} // namespace llvm
