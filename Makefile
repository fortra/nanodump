BOFNAME := nanodump
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
STRIP_x64 := x86_64-w64-mingw32-strip
STRIP_x86 := i686-w64-mingw32-strip
OPTIONS := -masm=intel -Wall -I include

nanodump: clean
	$(info ###### RELEASE ######)

	$(CC_x64) -c source/entry.c -o compiled/$(BOFNAME).x64.o       $(OPTIONS) -DNANO -DBOF
	$(STRIP_x64) --strip-unneeded compiled/$(BOFNAME).x64.o

#	$(CC_x86) -c source/entry.c -o compiled/$(BOFNAME).x86.o       $(OPTIONS) -DNANO -DBOF
#	$(STRIP_x86) --strip-unneeded compiled/$(BOFNAME).x86.o

	$(CC_x64)    source/entry.c -o compiled/$(BOFNAME).x64.exe     $(OPTIONS) -DNANO -DEXE
	$(STRIP_x64) --strip-all compiled/$(BOFNAME).x64.exe

	$(CC_x86)    source/entry.c -o compiled/$(BOFNAME).x86.exe     $(OPTIONS) -DNANO -DEXE
	$(STRIP_x86) --strip-all compiled/$(BOFNAME).x86.exe

	$(CC_x64)    source/entry.c -o compiled/$(BOFNAME)_ssp.x64.dll $(OPTIONS) -DNANO -DSSP -shared
	$(STRIP_x64) --strip-all compiled/$(BOFNAME)_ssp.x64.dll

	$(CC_x86)    source/entry.c -o compiled/$(BOFNAME)_ssp.x86.dll $(OPTIONS) -DNANO -DSSP -shared
	$(STRIP_x86) --strip-all compiled/$(BOFNAME)_ssp.x86.dll

	$(CC_x64) -c source/load_ssp.c -o compiled/load_ssp.x64.o      $(OPTIONS) -DLOADER -DBOF
	$(STRIP_x64) --strip-unneeded compiled/load_ssp.x64.o

	$(CC_x86) -c source/load_ssp.c -o compiled/load_ssp.x86.o      $(OPTIONS) -DLOADER -DBOF
	$(STRIP_x86) --strip-unneeded compiled/load_ssp.x86.o

	$(CC_x64)    source/load_ssp.c -o compiled/load_ssp.x64.exe    $(OPTIONS) -DLOADER -DEXE
	$(STRIP_x64) --strip-all compiled/load_ssp.x64.exe

	$(CC_x86)    source/load_ssp.c -o compiled/load_ssp.x86.exe    $(OPTIONS) -DLOADER -DEXE
	$(STRIP_x86) --strip-all compiled/load_ssp.x86.exe

debug: clean
	$(info ###### DEBUG ######)

	$(CC_x64) -c source/entry.c -o compiled/$(BOFNAME).x64.o       $(OPTIONS) -DNANO -DBOF -DDEBUG

#	$(CC_x86) -c source/entry.c -o compiled/$(BOFNAME).x86.o       $(OPTIONS) -DNANO -DBOF -DDEBUG

	$(CC_x64)    source/entry.c -o compiled/$(BOFNAME).x64.exe     $(OPTIONS) -DNANO -DEXE -DDEBUG

	$(CC_x86)    source/entry.c -o compiled/$(BOFNAME).x86.exe     $(OPTIONS) -DNANO -DEXE -DDEBUG

	$(CC_x64)    source/entry.c -o compiled/$(BOFNAME)_ssp.x64.dll $(OPTIONS) -DNANO -DSSP -shared -DDEBUG

	$(CC_x86)    source/entry.c -o compiled/$(BOFNAME)_ssp.x86.dll $(OPTIONS) -DNANO -DSSP -shared -DDEBUG

	$(CC_x64) -c source/load_ssp.c -o compiled/load_ssp.x64.o      $(OPTIONS) -DLOADER -DBOF -DDEBUG

	$(CC_x86) -c source/load_ssp.c -o compiled/load_ssp.x86.o      $(OPTIONS) -DLOADER -DBOF -DDEBUG

	$(CC_x64)    source/load_ssp.c -o compiled/load_ssp.x64.exe    $(OPTIONS) -DLOADER -DEXE -DDEBUG

	$(CC_x86)    source/load_ssp.c -o compiled/load_ssp.x86.exe    $(OPTIONS) -DLOADER -DEXE -DDEBUG

clean:
	rm -f compiled/*
