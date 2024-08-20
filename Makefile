afcsh: afcsh.c
	gcc -o build/afcsh afcsh.c error.c core_foundation_utils.c ext_string.c -framework CoreFoundation -g -O0

clean:
	rm build/*