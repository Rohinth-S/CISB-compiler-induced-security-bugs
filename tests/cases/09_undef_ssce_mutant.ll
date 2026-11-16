; CISBFuzz (EuroSec '26, Fig. 5) - Undef EarlyCSE Silent Security Check Erasure (SSCE)
; Seed pattern: integer overflow security gate checking %user_id
; Under EarlyCSE: '%cmp = icmp sgt i32 %val, %loaded' where %val is derived from undef
; causes the optimizer to treat the comparison as don't-care, folding 'br i1 %cmp' to 'br i1 false'!
; Mitigated with UndefFreezeGuardPass: inserts 'freeze' on undef operands to prevent branch erasure.

define i32 @security_gate(i32 %user_id) {
entry:
  %id.addr = alloca i32, align 4
  %val = add nsw i32 undef, 10
  store i32 %user_id, ptr %id.addr, align 4
  %loaded = load i32, ptr %id.addr, align 4
  %cmp = icmp sgt i32 %val, %loaded
  br i1 %cmp, label %passed, label %failed

passed:
  ret i32 0

failed:
  ret i32 1
}
