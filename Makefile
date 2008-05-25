# Makefile for MO-Eval
# (c) 2008 Martin Mares <mj@ucw.cz>

VERSION=1.0.99-20080220

# The default target
all: runtree programs datafiles configs

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
# Disable built-in tests of these libraries
TESTS=
endif

include $(s)/box/Makefile
include $(s)/utils/Makefile
include $(s)/eval/Makefile
include $(s)/judge/Makefile

ifdef CONFIG_SUBMIT
include $(s)/submit/Makefile
endif

ifdef CONFIG_MOP
include $(s)/mop/Makefile
endif

# And finally the default rules of the build system
include $(s)/build/Makebottom
