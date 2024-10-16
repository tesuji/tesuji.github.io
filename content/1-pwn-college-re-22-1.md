+++
title = "Not a step-by-step guide for Reverse engineering level 22.1"
date = 2024-10-16
+++

Like the title says it, and to be comply with pwn.college's about not posting solutions
to prevent students from directly copying the answer. There will be no code here, but
only a guide.

---

This challenge took me more than a day to solve it. So as they say, teaching is learning.
I'm writing this.

First, let's start the challenge in the website and connect to the workspace or to ssh
if you prefer.
```bash
# don't forget to ssh-add your ssh keys
ssh -i ~/.ssh/id_ed25519 hacker@dojo.pwn.college
```

My stupid ass forgot that I encrypt the key, and ssh just bail off connecting to the server
until I ssh-add the key and enter the password. So don't be like me!

Keep it mind that the binary analyzed at this time might not be the same as your, since `pwn.college`
authors could change it/recompile the source file.

```bash
> sha256sum  /challenge/babyrev_level22.1
1ffb9398208ac7468f7b5d51afb3e6c47818649a83b7e1cd38d8e0e34eccb8f9  /challenge/babyrev_level22.1
```

Load the binary into Ghidra or IDA to decompile. We could see that the yan code is encoded as `x, y, op`
format.

## Find the value of `imm` and `reg_i`

You're asking yourself how do you figure all the value of instructions, and registers, and syscall numbers.
We finding the easy one first, the `imm i 3` instruction.

Why "3"? 3 is not a power of 2, so it's an invalid reg value. This will make other instructions like
`add reg reg2`, or `stk`, `ldm` crash with a unknown registers error message.

Why finding "i" first? Because we have no easy way to distinguish `a, b, c, d, s, f` from the others.
But we can find both `imm` and `reg_i` at the same time, by using infinite loop. Consider the following
yan code:
```asm
NOP_INSN * 3
imm i 3
INVALID_INSN
```

where `NOP_INSN = [0xff, 0xff, 0x0]` and `INVALID_INSN = [3]*3`. You could see why `NOP_INSN` is a no-op
and why `INVALID_INSN` is an invalid one.

Just do a loop inside a loop to find the pair that makes the program stuck infinitely. That would be
our `imm` and `i` values.

From that, you could make another program to test for invalid reg values with this yancode:
```asm
imm reg 3 # remember to skip i from your range
imm i 1
```

Any regs (two) that crash the program is the invalid reg values that you could skip from your loop below.

## Find `stk`

Why? Because we need `stk` to do useful things like pushing filename for the open syscall to use.
If you have prior experience, you'll only need `imm`, `stk`, `sys` instruction to open, read
the flag and write it out to stdout.

How? By using this yan code, choose "X" - (maybe 0x1) - be something from your valid ranges.
```asm
imm X 3
stk 0 X => push X;
imm i 4
invalid
imm X 8
stk 0 X => push X;
stk i 0 => pop i = Y;
invalid
imm i 8
invalid * 20
```

Create a for loop over `1<<i for i in range(8) if 1<<i != op_imm` and check for the only one
that hang the program, that's our `stk` value. Why? Replace `stk` in line 2 of the snippet above with:
* `jmp` => `jmp 0 X` => jmp unconditionally with `i=X = 3`, which will crash.
* `ldm`, `add`, `cmp`, `stm` => `ldm 0 X` => crash with invalid reg "0".
* `sys` => `sys i 0`:
  + => If value `reg_i` is a syscall number that not equal to `sys_read` => crash with invalid reg "0".
  + => If not, the instruction fall-through at line 7 and crash invalid reg "0".
  We're lucky that `reg_i` is not a `sys_read`.

## Find `sys`

As before, here's the yan code (use the same 'X' as before if you like):
```asm
imm X 4
sys 0 X # noop
sys 3 X
imm i 1 # loop
invalid * 20
```

How it works? Replace `sys` at line 2 with any `jmp, add, cmp, ldm, stm` (like `add 0 X`),
we have a crash at invalid reg "0".
Find the only opcode that hang the program, that's our `op_sys` value.

## Find `sys_exit` and `reg_a`

Easy enough:
```asm
imm a 42
sys exit X # exit 42
invalid * 20
```

How? If the `sys_op` is `open|write|sleep`, it will return and execute `INVALID_INSN` next.
If `sys_op` is `read_code|read_mem`, we have `read(42, ..)` which fail immediately.
Just detect the case the program returns 42, we have `sys_exit` and `reg_a` value.

## Find invalid/no-op sys values

These value as syscall number do nothing, not even write to `y` reg (in `sys n y`).
```asm
imm a 42
sys n a
sys exit 0
```

The no-op ones will exit with code 42.

## Find `reg_s`

You're asking me why. Because we need to detect values of `b, c` to place the
correct argument for `open/read/write` syscalls. So filtering out valid values
of `b,c,d` by excluding `s,i,a,f` sound more doable.

By using this code:
```asm
imm a 0; stk 0 a
imm a 6; stk 0 a
# if reg is s; loop
imm s 1
stk i 0
invalid * 20
```

If the reg is `s`, we pop "0", not "6" from stack, makes the program loops.
If not, it will crash.

## Find `jmp` and `reg_f`

Same spirit:
```asm
imm a 4
imm f 1
jmp 1 a
invalid
imm i 4; loop
# if reg is f and op is jmp; loop
invalid * 20
```

## Find `sys_write` and `reg b, c`

By pushing "abcd\0" onto the stack, setting `b=1, c=5, a=1`,
checking what value make the program print "abcd".
Your thoughts are right! This will need 3 overlapping loops.
But fear not, we exclude the known ones: `reg a, i, s, f, invalids`
and `sys_exit, no-op ones`. The yan code left as a exercise for readers.

You have three value: `sys_write, b, c`.

## Find `sys_sleep`

The easy one? By measuring execution time (in seconds):
```asm
imm a 2
sys sleep a
invalid
```

## Find `sys_open`

I was expecting to open a valid file with `fd=3`. But the program already have 3 opened. So 4 returned by `open` syscall.

```asm
stk 0 a; * 4 # assert fd < 4 where fd in read fd
imm a 'a'; stk 0 a
imm a 0; stk 0 a
imm b O_RDONLY # which is 0 btw
imm a 4
sys open a
sys exit 0
```

Why do we "push 0" 4 times? To let the first argument "a" be 4, which contains "a\0" on stack.
Because if the syscall number is `read_mem|read_code`, `read(4,..)` will fail immediately.
So check if the program exit with 4, you're good.
Or with `a <= 3`, you could check whether the program hangs or not.

## Find `sys_read_mem` (and `sys_read_code` but we don't need it)

So, by filtering out `sys_exit, sleep, write, open`, and invalid ones.
We left with two remaining values for `read_mem` and `read_code`.
Both hangs the program for input. How do we different them?
```asm
imm c 0xff
imm b 4
imm a 0
sys read_mem a ; <= send bytes of imm a 15; sys exit 0
imm a 42
sys exit 0
```

# Conclusion

That's it. You have all the needed values. Go grab the flag!

It was a fun (and time-consuming) challenge.
Feel free to comment in my github blog for discussion.

