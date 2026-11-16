#include "ScrubGuardPass.h"
#include "UndefFreezePass.h"
#include "CFGVerifyPass.h"

#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"

using namespace llvm;

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION,
    "CISBGuardPlugin",
    LLVM_VERSION_STRING,
    [](PassBuilder &PB) {
      // 1. Pipeline Start Callbacks: Run before DSE and EarlyCSE
      PB.registerPipelineStartEPCallback([](ModulePassManager &MPM, OptimizationLevel Level) {
        FunctionPassManager FPM;
        FPM.addPass(ScrubGuardPass());
        FPM.addPass(UndefFreezePass());
        FPM.addPass(CFGVerifyPass(/*IsPostOpt=*/false));
        MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
      });

      // 2. Optimizer Last Callback: Verify security checks survived
      PB.registerOptimizerLastEPCallback([](ModulePassManager &MPM, OptimizationLevel Level) {
        FunctionPassManager FPM;
        FPM.addPass(CFGVerifyPass(/*IsPostOpt=*/true));
        MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
      });

      // 3. Command-line pipeline parsing for 'opt -passes=...'
      PB.registerPipelineParsingCallback(
        [](StringRef Name, FunctionPassManager &FPM, ArrayRef<PassBuilder::PipelineElement>) {
          if (Name == "cisb-scrub-guard") {
            FPM.addPass(ScrubGuardPass());
            return true;
          }
          if (Name == "cisb-undef-freeze") {
            FPM.addPass(UndefFreezePass());
            return true;
          }
          if (Name == "cisb-cfg-verify-pre") {
            FPM.addPass(CFGVerifyPass(/*IsPostOpt=*/false));
            return true;
          }
          if (Name == "cisb-cfg-verify-post") {
            FPM.addPass(CFGVerifyPass(/*IsPostOpt=*/true));
            return true;
          }
          if (Name == "cisb-guard-all") {
            FPM.addPass(ScrubGuardPass());
            FPM.addPass(UndefFreezePass());
            FPM.addPass(CFGVerifyPass(/*IsPostOpt=*/false));
            return true;
          }
          return false;
        }
      );
    }
  };
}
