# ELF Symbol Rename Utility Makefile

CC=gcc
LD=gcc
INDENT_FLAGS=-br -ce -i4 -bl -bli0 -bls -c4 -cdw -ci4 -cs -nbfda -l100 -lp -prs -nlp -nut -nbfde -npsl -nss

all: symrename

prepare:
	@mkdir -p bin

symrename: prepare
	@echo "  CC    symrename.c"
	@$(CC) -Wall -O2 -c src/symrename.c -o bin/symrename.o
	@echo "  LD    symrename"
	@$(LD) bin/symrename.o -o bin/symrename

analyse:
	@cppcheck src/symrename.c
	@scan-build make

install:
	@cp symrename /usr/bin/symrename

uninstall:
	@rm -f /usr/bin/symrename

indent:
	@find ./ -type f -exec touch {} +
	@indent $(INDENT_FLAGS) src/symrename.c
	@rm -fv src/*~

clean:
	@echo "  CLEAN ."
	@rm -rf bin
