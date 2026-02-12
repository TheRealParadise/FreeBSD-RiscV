.PATH: ${SRCTOP}/sys/dev/pwm/controller/sifive

KMOD=	sf_pwm
SRCS=	sf_pwm.c

SRCS+=	\
	bus_if.h \
	clknode_if.h \
	device_if.h \
	ofw_bus_if.h \
	pwmbus_if.h

beforedepend:
	@-/bin/echo "#define FDT 0" > opt_platform.h

.include <bsd.kmod.mk>
