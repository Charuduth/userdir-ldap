.SILENT:

MANPAGES = ud-generate.8 ud-gpgimport.8 ud-info.1 ud-xearth.1 ud-useradd.8 \
           ud-userimport.8 ud-mailgate.8

all: $(MANPAGES)

$(MANPAGES) :: % : %.yo
	echo Creating man page $@
	yodl2man -o $@ $<
		
clean:
	rm -f $(MANPAGES)
