BOFNAME := nanodump
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
STRIP_x64 := x86_64-w64-mingw32-strip
STRIP_x86 := i686-w64-mingw32-strip
OPTIONS := -masm=intel -Wall -I include

nanodump: clean
	$(CC_x64) -c source/nanodump.c -o compiled/$(BOFNAME).x64.o $(OPTIONS) -DBOF
	$(STRIP_x64) --strip-unneeded compiled/$(BOFNAME).x64.o

#	$(CC_x86) -c source/nanodump.c -o compiled/$(BOFNAME).x86.o   -masm=intel -Wall -DBOF
#	$(STRIP_x86) --strip-unneeded compiled/$(BOFNAME).x86.o

	$(CC_x64)    source/nanodump.c -o compiled/$(BOFNAME).x64.exe $(OPTIONS)
	$(STRIP_x64) --strip-all compiled/$(BOFNAME).x64.exe

	$(CC_x86)    source/nanodump.c -o compiled/$(BOFNAME).x86.exe $(OPTIONS)
	$(STRIP_x86) --strip-all compiled/$(BOFNAME).x86.exe

debug: clean
	$(CC_x64) -c source/nanodump.c -o compiled/$(BOFNAME).x64.o $(OPTIONS) -DBOF -DDEBUG
	$(STRIP_x64) --strip-unneeded compiled/$(BOFNAME).x64.o

#	$(CC_x86) -c source/nanodump.c -o compiled/$(BOFNAME).x86.o   -masm=intel -Wall -DBOF -DDEBUG
#	$(STRIP_x86) --strip-unneeded compiled/$(BOFNAME).x86.o

	$(CC_x64)    source/nanodump.c -o compiled/$(BOFNAME).x64.exe $(OPTIONS) -DDEBUG
	$(STRIP_x64) --strip-all compiled/$(BOFNAME).x64.exe

	$(CC_x86)    source/nanodump.c -o compiled/$(BOFNAME).x86.exe $(OPTIONS) -DDEBUG
	$(STRIP_x86) --strip-all compiled/$(BOFNAME).x86.exe

clean:
	rm compiled/*
