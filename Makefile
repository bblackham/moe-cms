# Makefile for MO-Eval
# (c) 2008 Martin Mares <mj@ucw.cz>

VERSION=1.0.99-20080220

# The default target
all: runtree programs

# Include configuration
s=.
-include obj/config.mk
obj/config.mk:
	@echo "You need to run configure first." && false

# We will use the libucw build system
include $(s)/build/Maketop

# Include makefiles of libraries we wish to use
ifdef CONFIG_UCW_LIBS
include $(s)/lib/Makefile
include $(s)/sherlock/Makefile
endif

include $(s)/box/Makefile

# And finally the default rules of the build system
include $(s)/build/Makebottom
