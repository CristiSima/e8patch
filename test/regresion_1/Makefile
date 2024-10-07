CC 			?= gcc
CFLAGS 		?= -O0
TOOL_PATH 	?= ../../src/main.py
CHECKER		 = python ../check.py

eq = $(and $(findstring $(1),$(2)),$(findstring $(2),$(1)))

base:
	$(CC) $(CFLAGS) base.c -o base

compile: base

build: compile
	python $(TOOL_PATH) base patch.c -o patched

run: build
	./patched > patched.out

compare: run
	grep 'new_6:' patched.out
	$(CHECKER) patched.exp patched.out

clean: clean_bins clean_outs

clean_outs:
	rm *.out > /dev/null || true

clean_bins:
	rm base patched src_patched *_no-plt *.o > /dev/null || true