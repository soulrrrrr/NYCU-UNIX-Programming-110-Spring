all:
	gcc -c -g -Wall -masm=intel -fno-stack-protector -fPIC -nostdlib libmini.c
	yasm -f elf64 -DYASM -D__x86_64__ -DPIC libmini64.asm -o libmini64.o
	ld -shared -o libmini.so libmini64.o libmini.o
	yasm -f elf64 -DYASM -D__x86_64__ -DPIC start.asm -o start.o
	gcc -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI jmp2.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o jmp2 jmp2.o start.o -L. -L.. -lmini
	rm jmp2.o
clean:
	rm -f a.out *.o $(PROGS) peda-*

