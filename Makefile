afcsh: afcsh.c
	gcc -o build/afcsh afcsh.c afcsh_helpers.c afcsh_commands.c error.c ext_string.c core_foundation_utils.c -framework CoreFoundation

clean:
	rm build/*