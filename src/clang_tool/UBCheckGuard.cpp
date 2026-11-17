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
#include <string>

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::tooling;
using namespace llvm;

static cl::OptionCategory CISBGuardCategory("CISB-Guard Clang Rewriter Options");
static cl::opt<std::string> OutputFilename("o", cl::desc("Specify output rewritten C file"), cl::value_desc("filename"), cl::cat(CISBGuardCategory));

static std::string trimParensAndSpace(StringRef S) {
  S = S.trim();
  while (S.starts_with("(") && S.ends_with(")")) {
    S = S.drop_front(1).drop_back(1).trim();
  }
  return S.str();
}

// Handler 1: Signed Overflow Guard
// Rewrites: if (x + c < x) -> if (__builtin_add_overflow((x), (c), &(int){0}))
//           if (a + c > a) -> if (!__builtin_add_overflow((a), (c), &(int){0}) && ((c) > 0))
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
    if (!SM.isInMainFile(Start) || Start.isMacroID()) return;

    // Only apply to signed integer addition
    if (!AddOp->getType()->isSignedIntegerType()) return;

    std::string LHSText = Lexer::getSourceText(CharSourceRange::getTokenRange(AddOp->getLHS()->getSourceRange()), SM, Result.Context->getLangOpts()).str();
    std::string RHSText = Lexer::getSourceText(CharSourceRange::getTokenRange(AddOp->getRHS()->getSourceRange()), SM, Result.Context->getLangOpts()).str();
    std::string CmpRHSText = Lexer::getSourceText(CharSourceRange::getTokenRange(BinOp->getRHS()->getSourceRange()), SM, Result.Context->getLangOpts()).str();

    std::string CleanLHS = trimParensAndSpace(LHSText);
    std::string CleanRHS = trimParensAndSpace(RHSText);
    std::string CleanCmpRHS = trimParensAndSpace(CmpRHSText);

    // Overflow check must compare (A + B) against either A or B
    if (CleanCmpRHS != CleanLHS && CleanCmpRHS != CleanRHS) return;

    std::string Replacement;
    if (BinOp->getOpcode() == BO_LT) {
      Replacement = "__builtin_add_overflow((" + LHSText + "), (" + RHSText + "), &(int){0})";
    } else if (BinOp->getOpcode() == BO_GT) {
      std::string IncText = (CleanCmpRHS == CleanLHS) ? RHSText : LHSText;
      Replacement = "(!__builtin_add_overflow((" + LHSText + "), (" + RHSText + "), &(int){0}) && ((" + IncText + ") > 0))";
    } else {
      return;
    }

    Rewrite.ReplaceText(SourceRange(Start, End), Replacement);
    llvm::errs() << "[CISB-Guard:UBCheckGuard] Rewrote signed overflow check to __builtin_add_overflow\n";
  }
};

// AST Visitor to detect if a pointer was dereferenced before a given location
class PriorDerefVisitor : public RecursiveASTVisitor<PriorDerefVisitor> {
  const ValueDecl *TargetVD;
  SourceLocation TargetLoc;
  SourceManager &SM;
  bool FoundPriorDeref = false;

public:
  PriorDerefVisitor(const ValueDecl *VD, SourceLocation Loc, SourceManager &SM)
    : TargetVD(VD), TargetLoc(Loc), SM(SM) {}

  bool VisitUnaryOperator(UnaryOperator *UO) {
    if (UO->getOpcode() == UO_Deref) {
      if (const auto *DRE = dyn_cast<DeclRefExpr>(UO->getSubExpr()->IgnoreParenImpCasts())) {
        if (DRE->getDecl() == TargetVD) {
          if (SM.isBeforeInTranslationUnit(UO->getBeginLoc(), TargetLoc)) {
            FoundPriorDeref = true;
            return false;
          }
        }
      }
    }
    return true;
  }

  bool VisitMemberExpr(MemberExpr *ME) {
    if (ME->isArrow()) {
      if (const auto *DRE = dyn_cast<DeclRefExpr>(ME->getBase()->IgnoreParenImpCasts())) {
        if (DRE->getDecl() == TargetVD) {
          if (SM.isBeforeInTranslationUnit(ME->getBeginLoc(), TargetLoc)) {
            FoundPriorDeref = true;
            return false;
          }
        }
      }
    }
    return true;
  }

  bool hasPriorDeref() const { return FoundPriorDeref; }
};

// Handler 2: Post-Dereference Null Check Guard
// Inserts: __asm__ __volatile__("" : "+r"(p)); before if (!p) or if (p == NULL)
class PostDerefNullHandler : public MatchFinder::MatchCallback {
  Rewriter &Rewrite;
public:
  explicit PostDerefNullHandler(Rewriter &R) : Rewrite(R) {}

  void run(const MatchFinder::MatchResult &Result) override {
    const auto *FD = Result.Nodes.getNodeAs<FunctionDecl>("enclosing_fn");
    const auto *If = Result.Nodes.getNodeAs<IfStmt>("null_if");
    const auto *Ptr = Result.Nodes.getNodeAs<Expr>("null_ptr");
    const auto *NullRHS = Result.Nodes.getNodeAs<Expr>("null_rhs");
    if (!If || !Ptr || !FD) return;

    SourceManager &SM = *Result.SourceManager;
    SourceLocation IfLoc = If->getBeginLoc();
    if (!SM.isInMainFile(IfLoc) || IfLoc.isMacroID()) return;

    if (NullRHS && !NullRHS->isNullPointerConstant(*Result.Context, Expr::NPC_ValueDependentIsNotNull)) {
      return;
    }

    if (!Ptr->getType()->isPointerType()) return;

    const auto *DRE = dyn_cast<DeclRefExpr>(Ptr->IgnoreParenImpCasts());
    if (!DRE) return;
    const ValueDecl *VD = DRE->getDecl();
    if (!VD) return;

    PriorDerefVisitor Visitor(VD, IfLoc, SM);
    Visitor.TraverseDecl(const_cast<FunctionDecl *>(FD));
    if (!Visitor.hasPriorDeref()) return;

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
    SourceLocation AddBegin = Add->getBeginLoc();
    SourceLocation AddEnd = Add->getEndLoc();
    if (!SM.isInMainFile(AddBegin) || AddBegin.isMacroID()) return;

    const Expr *SubLHS = Add->getLHS()->IgnoreParenImpCasts();
    QualType OrigType = SubLHS->getType();

    if (!OrigType->isIntegerType()) return;
    if (Result.Context->getTypeSize(OrigType) >= Result.Context->getTypeSize(Result.Context->IntTy)) return;

    std::string TypeName = OrigType.getAsString();
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

    // 1. Matcher for signed overflow: (x + c < x) or (a + c > a)
    auto AddExpr = binaryOperator(
      hasOperatorName("+"),
      hasLHS(expr().bind("add_lhs")),
      hasRHS(expr().bind("add_rhs"))
    ).bind("add_op");

    Matcher.addMatcher(
      binaryOperator(
        anyOf(hasOperatorName("<"), hasOperatorName(">")),
        hasLHS(AddExpr),
        hasRHS(expr().bind("cmp_rhs"))
      ).bind("overflow_cmp"),
      &OverflowHandler
    );

    // 2. Matcher for post-dereference null check in enclosing function
    Matcher.addMatcher(
      functionDecl(forEachDescendant(
        ifStmt(
          hasCondition(
            anyOf(
              unaryOperator(hasOperatorName("!"), hasUnaryOperand(expr().bind("null_ptr"))),
              binaryOperator(hasOperatorName("=="), hasLHS(expr().bind("null_ptr")), hasRHS(expr().bind("null_rhs")))
            )
          )
        ).bind("null_if")
      )).bind("enclosing_fn"),
      &NullHandler
    );

    // 3. Matcher for narrow promotion: (u8 + 1 == 0)
    Matcher.addMatcher(
      binaryOperator(
        hasOperatorName("=="),
        hasLHS(
          binaryOperator(
            hasOperatorName("+")
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

    const RewriteBuffer *RewriteBuf = Rewrite.getRewriteBufferFor(SM.getMainFileID());
    if (RewriteBuf) {
      RewriteBuf->write(OS);
    } else {
      OS << SM.getBufferData(SM.getMainFileID());
    }

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
