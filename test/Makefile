CC = gcc
CFLAGS = -O0 
TOOL_PATH = ../src/main.py
.PHONY: 0 1 2 3 4 5 regresion

0:
	make -C 0 compare

1:
	make -C 1 compare

2:
	make -C 2 compare

3:
	make -C 3 compare

4:
	make -C 4 compare

5:
	make -C 5 compare

regresion:
	make -C regresion_1 compare

test: 0 1 2 3 4 5 regresion

clean:
	make -C 0 clean
	make -C 1 clean
	make -C 2 clean
	make -C 3 clean
	make -C 4 clean
	make -C 5 clean
	make -C regresion_1 clean

# compare() { colordiff -W 200 --difftype=diffy -y <( $@ ./base) <( $@ ./patched)|nl; }
# compare_no-plt() { colordiff -W 200 --difftype=diffy -y <( $@ ./base_no-plt) <( $@ ./patched_no-plt)|nl; }
