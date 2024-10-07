CC 			?= gcc
CFLAGS 		?= -O0
TOOL_PATH 	?= ../../src/main.py
CHECKER		 = python ../check.py

eq = $(and $(findstring $(1),$(2)),$(findstring $(2),$(1)))

base:
	$(CC) $(CFLAGS) base.c -o base
src_patched:
	$(CC) $(CFLAGS) src_patched.c -o src_patched
base_no-plt:
	$(CC) $(CFLAGS) base.c -o base_no-plt -fno-plt
src_patched_no-plt:
	$(CC) $(CFLAGS) src_patched.c -o src_patched_no-plt -fno-plt

compile: base src_patched base_no-plt src_patched_no-plt

build: compile
	python $(TOOL_PATH) base patch.c -o patched
	python $(TOOL_PATH) base_no-plt patch.c -o patched_no-plt

	# rm *.o

run: build
	./patched > patched.out
	./patched_no-plt > patched_no-plt.out

	./src_patched > src_patched.out
	./src_patched_no-plt > src_patched_no-plt.out

compare: run
	$(CHECKER) out.exp src_patched.out
	$(CHECKER) out.exp src_patched_no-plt.out

	$(CHECKER) out.exp patched.out
	$(CHECKER) out.exp patched_no-plt.out

clean: clean_bins clean_outs

clean_outs:
	rm *.out > /dev/null || true

clean_bins:
	rm base patched src_patched *_no-plt *.o > /dev/null || true