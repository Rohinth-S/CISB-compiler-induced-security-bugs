#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

#include <iostream>
#include <fstream>

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::tooling;
using namespace llvm;

static cl::OptionCategory CISBGuardCategory("CISB-Guard Clang Rewriter Options");
static cl::opt<std::string> OutputFilename("o", cl::desc("Specify output rewritten C file"), cl::value_desc("filename"), cl::cat(CISBGuardCategory));

// Handler 1: Signed Overflow Guard
// Rewrites: if (x + c < x) -> if (((long long)(x) + (long long)(c)) < (long long)(x))
class SignedOverflowHandler : public MatchFinder::MatchCallback {
  Rewriter &Rewrite;
public:
  explicit SignedOverflowHandler(Rewriter &R) : Rewrite(R) {}

  void run(const MatchFinder::MatchResult &Result) override {
    const auto *BinOp = Result.Nodes.getNodeAs<BinaryOperator>("overflow_cmp");
    const auto *AddOp = Result.Nodes.getNodeAs<BinaryOperator>("add_op");
    if (!BinOp || !AddOp) return;

    SourceManager &SM = *Result.SourceManager;
    SourceLocation Start = BinOp->getBeginLoc();
    SourceLocation End = BinOp->getEndLoc();

    std::string LHSText = Lexer::getSourceText(CharSourceRange::getTokenRange(AddOp->getLHS()->getSourceRange()), SM, Result.Context->getLangOpts()).str();
    std::string RHSText = Lexer::getSourceText(CharSourceRange::getTokenRange(AddOp->getRHS()->getSourceRange()), SM, Result.Context->getLangOpts()).str();

    // Replace with __builtin_add_overflow
    std::string Replacement = "__builtin_add_overflow((" + LHSText + "), (" + RHSText + "), &(int){0})";
    Rewrite.ReplaceText(SourceRange(Start, End), Replacement);
    llvm::errs() << "[CISB-Guard:UBCheckGuard] Rewrote signed overflow check to __builtin_add_overflow\n";
  }
};

// Handler 2: Post-Dereference Null Check Guard
// Inserts: __asm__ __volatile__("" : "+r"(p)); before if (!p) or if (p == NULL)
class PostDerefNullHandler : public MatchFinder::MatchCallback {
  Rewriter &Rewrite;
public:
  explicit PostDerefNullHandler(Rewriter &R) : Rewrite(R) {}

  void run(const MatchFinder::MatchResult &Result) override {
    const auto *If = Result.Nodes.getNodeAs<IfStmt>("null_if");
    const auto *Ptr = Result.Nodes.getNodeAs<Expr>("null_ptr");
    if (!If || !Ptr) return;

    SourceManager &SM = *Result.SourceManager;
    SourceLocation IfLoc = If->getBeginLoc();

    std::string PtrText = Lexer::getSourceText(CharSourceRange::getTokenRange(Ptr->getSourceRange()), SM, Result.Context->getLangOpts()).str();
    std::string Barrier = "__asm__ __volatile__(\"\" : \"+r\"(" + PtrText + "));\n    ";

    Rewrite.InsertTextBefore(IfLoc, Barrier);
    llvm::errs() << "[CISB-Guard:UBCheckGuard] Inserted compiler barrier before post-dereference null check on " << PtrText << "\n";
  }
};

// Handler 3: Narrow Integer Promotion Guard
// Rewrites: if (u8 + 1 == 0) -> if ((uint8_t)(u8 + 1) == 0)
class NarrowPromotionHandler : public MatchFinder::MatchCallback {
  Rewriter &Rewrite;
public:
  explicit NarrowPromotionHandler(Rewriter &R) : Rewrite(R) {}

  void run(const MatchFinder::MatchResult &Result) override {
    const auto *Cmp = Result.Nodes.getNodeAs<BinaryOperator>("promoted_cmp");
    const auto *Add = Result.Nodes.getNodeAs<BinaryOperator>("promoted_add");
    if (!Cmp || !Add) return;

    SourceManager &SM = *Result.SourceManager;
    QualType QT = Add->getLHS()->getType();
    std::string TypeName = QT.getAsString();

    SourceLocation AddBegin = Add->getBeginLoc();
    SourceLocation AddEnd = Add->getEndLoc();

    std::string AddText = Lexer::getSourceText(CharSourceRange::getTokenRange(SourceRange(AddBegin, AddEnd)), SM, Result.Context->getLangOpts()).str();
    std::string Replacement = "((" + TypeName + ")(" + AddText + "))";

    Rewrite.ReplaceText(SourceRange(AddBegin, AddEnd), Replacement);
    llvm::errs() << "[CISB-Guard:UBCheckGuard] Inserted explicit narrowing cast for promoted integer arithmetic: " << TypeName << "\n";
  }
};

class CISBASTConsumer : public ASTConsumer {
  MatchFinder Matcher;
  Rewriter &Rewrite;
  SignedOverflowHandler OverflowHandler;
  PostDerefNullHandler NullHandler;
  NarrowPromotionHandler PromotionHandler;

public:
  CISBASTConsumer(Rewriter &R)
    : Rewrite(R),
      OverflowHandler(R),
      NullHandler(R),
      PromotionHandler(R) {

    // 1. Matcher for signed overflow: (x + c < x)
    auto AddExpr = binaryOperator(
      hasOperatorName("+"),
      hasLHS(expr().bind("add_lhs")),
      hasRHS(expr().bind("add_rhs"))
    ).bind("add_op");

    Matcher.addMatcher(
      binaryOperator(
        hasOperatorName("<"),
        hasLHS(AddExpr),
        hasRHS(expr())
      ).bind("overflow_cmp"),
      &OverflowHandler
    );

    // 2. Matcher for null check in IfStmt: if (!p) or if (p == 0)
    Matcher.addMatcher(
      ifStmt(
        hasCondition(
          anyOf(
            unaryOperator(hasOperatorName("!"), hasUnaryOperand(expr().bind("null_ptr"))),
            binaryOperator(hasOperatorName("=="), hasLHS(expr().bind("null_ptr")), hasRHS(integerLiteral(equals(0))))
          )
        )
      ).bind("null_if"),
      &NullHandler
    );

    // 3. Matcher for narrow promotion: (u8 + 1 == 0)
    Matcher.addMatcher(
      binaryOperator(
        hasOperatorName("=="),
        hasLHS(
          binaryOperator(
            hasOperatorName("+"),
            hasLHS(hasType(isUnsignedInteger()))
          ).bind("promoted_add")
        ),
        hasRHS(integerLiteral(equals(0)))
      ).bind("promoted_cmp"),
      &PromotionHandler
    );
  }

  void HandleTranslationUnit(ASTContext &Context) override {
    Matcher.matchAST(Context);
  }
};

class CISBFrontendAction : public ASTFrontendAction {
  Rewriter Rewrite;
public:
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI, StringRef file) override {
    Rewrite.setSourceMgr(CI.getSourceManager(), CI.getLangOpts());
    return std::make_unique<CISBASTConsumer>(Rewrite);
  }

  void EndSourceFileAction() override {
    SourceManager &SM = Rewrite.getSourceMgr();
    std::string OutStr;
    raw_string_ostream OS(OutStr);
    Rewrite.getEditBuffer(SM.getMainFileID()).write(OS);

    if (!OutputFilename.empty()) {
      std::error_code EC;
      raw_fd_ostream FileOS(OutputFilename, EC);
      if (!EC) {
        FileOS << OutStr;
      } else {
        llvm::errs() << "Error writing to " << OutputFilename << ": " << EC.message() << "\n";
      }
    } else {
      llvm::outs() << OutStr;
    }
  }
};

int main(int argc, const char **argv) {
  auto ExpectedParser = CommonOptionsParser::create(argc, argv, CISBGuardCategory);
  if (!ExpectedParser) {
    llvm::errs() << ExpectedParser.takeError();
    return 1;
  }
  CommonOptionsParser &OptionsParser = ExpectedParser.get();
  ClangTool Tool(OptionsParser.getCompilations(), OptionsParser.getSourcePathList());

  return Tool.run(newFrontendActionFactory<CISBFrontendAction>().get());
}
