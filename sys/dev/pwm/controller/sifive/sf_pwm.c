/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Stefan Rink 
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/rman.h>
#include <sys/resource.h>
#include <machine/bus.h>

#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <dev/clk/clk.h>
#include <dev/pwm/pwmc.h>
#include "pwmbus_if.h"

#define BITS_PER_LONG 64
#define __bf_shf(x) (__builtin_ffsll(x) - 1)
#define FIELD_FIT(_mask, _val)						  \
	({								  \
		!((((typeof(_mask))_val) << __bf_shf(_mask)) & ~(_mask)); \
	})
#define FIELD_PREP(_mask, _val)						\
	({								\
		((typeof(_mask))(_val) << __bf_shf(_mask)) & (_mask);	\
	})


#define GENMASK(h, l) (((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))
#define BIT(nr)			(1UL << (nr))

#define PWM_SIFIVE_PWMCFG_SCALE         GENMASK(3, 0)
#define PWM_SIFIVE_PWMCFG_STICKY        BIT(8)
#define PWM_SIFIVE_PWMCFG_ZEROCMP       BIT(9)
#define PWM_SIFIVE_PWMCFG_DEGLITCH      BIT(10)
#define PWM_SIFIVE_PWMCFG_EN_ALWAYS     BIT(12)
#define PWM_SIFIVE_PWMCFG_EN_ONCE       BIT(13)
#define PWM_SIFIVE_PWMCFG_CENTER        BIT(16)
#define PWM_SIFIVE_PWMCFG_GANG          BIT(24)
#define PWM_SIFIVE_PWMCFG_IP            BIT(28)

#define PWM_SIFIVE_CMPWIDTH             16

#define NS_PER_SEC      10000000ULL

static struct ofw_compat_data compat_data[] = {
	{ "sifive,fu740-c000-pwm",		1 },
	{ NULL,					0 }
};

static struct resource_spec sf_pwm_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ -1, 0 }
};

typedef struct {
	uint32_t	pwmcfg;
	uint32_t	_reserved0;
	uint32_t	pwmcount;
	uint32_t	_reserved1;
	uint32_t	pwms;
	uint32_t	_reserved2[3];
	uint32_t	pwmcmp[4];
} sf_pwm_regs;

struct sf_pwm_softc {
	device_t	dev;
	device_t	busdev;
	clk_t		clk;
	union {
	 struct resource  *res;
	 sf_pwm_regs	*regs;
	};
	uint64_t	clk_freq;
	unsigned int	period[4];
	unsigned int	duty[4];
	uint32_t	frac[4];
	uint32_t	flags;
	bool		enabled[4];
	bool		inverted[4];
};

#define	SF_PWM_READ(sc, reg)		bus_read_4((sc)->res, (reg))
#define	SF_PWM_WRITE(sc, reg, val)	bus_write_4((sc)->res, (reg), (val))

static int sf_pwm_probe(device_t dev);
static int sf_pwm_attach(device_t dev);
static int sf_pwm_detach(device_t dev);

static int sf_pwm_probe(device_t dev) {
	if (!ofw_bus_status_okay(dev)) return (ENXIO);
	if (!ofw_bus_search_compatible(dev, compat_data)->ocd_data) return (ENXIO);

	device_set_desc(dev, "SiFive PWM");
	return (BUS_PROBE_DEFAULT);
}

static int sf_pwm_attach(device_t dev) {
	struct sf_pwm_softc *sc;
	phandle_t node;
	int error;

	sc = device_get_softc(dev);
	sc->dev = dev;

        error = clk_get_by_ofw_index(dev, 0, 0, &sc->clk);
        if (error != 0) {
                device_printf(dev, "cannot get clock\n");
                goto fail;
        }
	error = clk_enable(sc->clk);
	if (error != 0) {
		device_printf(dev, "cannot enable clock\n");
		goto fail;
	}

        error = clk_get_freq(sc->clk, &sc->clk_freq);
        if (error != 0) {
                device_printf(dev, "cannot get clock frequency\n");
                goto fail;
        }

	if (bus_alloc_resources(dev, sf_pwm_spec, &sc->res) != 0) {
		device_printf(dev, "cannot allocate resources for device\n");
		error = ENXIO;
		goto fail;
	}

	/* Read the configuration left by U-Boot */
	//uint32_t reg = sc->regs->pwmcfg;	
	//device_printf(dev, "%x\n", reg);

//skipcfg:
	/*
	 * Note that we don't check for failure to attach pwmbus -- even without
	 * it we can still service clients who connect via fdt xref data.
	 */
	node = ofw_bus_get_node(dev);
	OF_device_register_xref(OF_xref_from_node(node), dev);

	sc->busdev = device_add_child(dev, "pwmbus", DEVICE_UNIT_ANY);

	for(int i=0; i<4; i++) sc->inverted[i]=true;

	bus_attach_children(dev);

	return (0);

fail:
	sf_pwm_detach(dev);
	return (error);
}

static int sf_pwm_detach(device_t dev) {
	struct sf_pwm_softc *sc;
	int error;

	sc = device_get_softc(dev);

	if ((error = bus_generic_detach(sc->dev)) != 0) {
		device_printf(sc->dev, "cannot detach child devices\n");
		return (error);
	}

	if (sc->res != NULL) bus_release_resources(dev, sf_pwm_spec, &sc->res);

	return (0);
}

static phandle_t sf_pwm_get_node(device_t bus, device_t dev) {
	return ofw_bus_get_node(bus);
}

static int sf_pwm_channel_count(device_t dev, u_int *nchannel) {
	*nchannel = 4;
	return (0);
}

static int sf_pwm_channel_config(device_t dev, u_int channel, u_int period, u_int duty) {
	struct sf_pwm_softc *sc = device_get_softc(dev);

	uint64_t scale_pow;
	unsigned long long num;
	uint32_t scale, frac, val=0;

	if(channel > 3) return(EINVAL);


	scale_pow = ((uint64_t)sc->clk_freq * period) / NS_PER_SEC;
	val = (scale_pow > 0) ? (flsl(scale_pow) - 1) : 0;
	int s = val - PWM_SIFIVE_CMPWIDTH;
	scale = (s < 0) ? 0 : (s > 0xf ? 0xf : s);

	num = (uint64_t)duty * (1U << PWM_SIFIVE_CMPWIDTH);
	frac = (num + (period / 2)) / period; /* Manual DIV_ROUND_CLOSEST */

	if (frac > (1U << PWM_SIFIVE_CMPWIDTH) - 1) frac = (1U << PWM_SIFIVE_CMPWIDTH) - 1;
	if(sc->inverted[channel]) frac = (1U << PWM_SIFIVE_CMPWIDTH) - 1 - frac;

	uint32_t cfg = (FIELD_PREP(PWM_SIFIVE_PWMCFG_SCALE, scale) | PWM_SIFIVE_PWMCFG_EN_ALWAYS); // | PWM_SIFIVE_PWMCFG_ZEROCMP); // ZEROCMP ensures it resets at CMP0
    
	SF_PWM_WRITE(sc, 0x00, cfg);
	SF_PWM_WRITE(sc, 0x20 + (4 * channel), frac);
 
	sc->frac[channel] = frac;
	sc->period[channel] = period;
	sc->duty[channel] = duty;

	return (0);
}

static int sf_pwm_channel_get_config(device_t dev, u_int channel, u_int *period, u_int *duty) {
	struct sf_pwm_softc *sc;
	sc = device_get_softc(dev);

	*period = sc->period[channel];
	*duty = sc->duty[channel];

	return (0);
}

static int sf_pwm_channel_enable(device_t dev, u_int channel, bool enable) {
	struct sf_pwm_softc *sc;

	if(channel > 3) return(EINVAL);

	sc = device_get_softc(dev);

	if (enable && sc->enabled[channel]) return (0);

	if (enable)
		SF_PWM_WRITE(sc, 0x20+4*channel, sc->frac[channel]);
	else
		SF_PWM_WRITE(sc, 0x20+4*channel, 0xFFFF);

	sc->enabled[channel] = enable;

	return (0);
}

static int sf_pwm_channel_is_enabled(device_t dev, u_int channel, bool *enabled) {
	struct sf_pwm_softc *sc;

	sc = device_get_softc(dev);

	*enabled = sc->enabled[channel];

	return (0);
}

static int sf_pwm_set_flags(device_t dev, u_int channel, uint32_t flags) {
	struct sf_pwm_softc *sc = device_get_softc(dev);
	if(channel > 3) return(EINVAL);						// We only have 4 channels
	if(~PWM_POLARITY_INVERTED & flags) return(EINVAL);			// We only accept invert
	sc->inverted[channel]=(PWM_POLARITY_INVERTED & flags)?true:false;	// Make it so
	return(0);
}

static int sf_pwm_get_flags(device_t dev, u_int channel, uint32_t *flags) {
	struct sf_pwm_softc *sc = device_get_softc(dev);
	if(channel > 3) return(EINVAL);						// Don't be greedy..
        *flags = sc->inverted[channel]?PWM_POLARITY_INVERTED:0;			// Give back the flags
        return (0);
}


static device_method_t sf_pwm_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		sf_pwm_probe),
	DEVMETHOD(device_attach,	sf_pwm_attach),
	DEVMETHOD(device_detach,	sf_pwm_detach),

	/* ofw_bus interface */
	DEVMETHOD(ofw_bus_get_node,	sf_pwm_get_node),

	/* pwmbus interface */
	DEVMETHOD(pwmbus_channel_get_flags,	sf_pwm_get_flags),
	DEVMETHOD(pwmbus_channel_set_flags,	sf_pwm_set_flags),
	DEVMETHOD(pwmbus_channel_count,		sf_pwm_channel_count),
	DEVMETHOD(pwmbus_channel_config,	sf_pwm_channel_config),
	DEVMETHOD(pwmbus_channel_get_config,	sf_pwm_channel_get_config),
	DEVMETHOD(pwmbus_channel_enable,	sf_pwm_channel_enable),
	DEVMETHOD(pwmbus_channel_is_enabled,	sf_pwm_channel_is_enabled),

	DEVMETHOD_END
};

static driver_t sf_pwm_driver = {
	"pwm",
	sf_pwm_methods,
	sizeof(struct sf_pwm_softc),
};

DRIVER_MODULE(sf_pwm, simplebus, sf_pwm_driver, 0, 0);
MODULE_DEPEND(sf_pwm, pwmbus, 1, 1, 1);
MODULE_VERSION(sf_pwm, 1);
SIMPLEBUS_PNP_INFO(compat_data);
