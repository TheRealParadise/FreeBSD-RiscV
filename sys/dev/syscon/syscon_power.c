/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 Jessica Clarke <jrtc27@FreeBSD.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Driver for simple syscon poweroff and reset devices. The device tree
 * specifications are fully described at:
 *
 * https://www.kernel.org/doc/Documentation/devicetree/bindings/power/reset/syscon-poweroff.txt
 * https://www.kernel.org/doc/Documentation/devicetree/bindings/power/reset/syscon-reboot.txt
 */

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/types.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/reboot.h>

#include <machine/bus.h>

#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#include <dev/ofw/openfirm.h>

#include "syscon_if.h"
#include "syscon.h"

#include <dev/iicbus/iicbus.h>
#include <dev/iicbus/iiconf.h>
#include "iicbus_if.h"

struct syscon_power_softc {
	struct syscon		*regmap;
	uint32_t		offset;
	uint32_t		value;
	uint32_t		mask;
	bool			reboot;
	eventhandler_tag	shutdown_tag;
};

static void syscon_power_shutdown_final(device_t dev, int howto){

//	struct syscon_power_softc *sc;
//	bool write;

	uint8_t data[2];

	device_t bus=device_find_child(root_bus, "nexus", 0);
	if(!bus){
		device_printf(dev, "Can't find nexus\n");
		return;
	}
	bus=device_find_child(bus, "ofwbus", 0);
	if(!bus){
		device_printf(dev, "Can't find ofwbus\n");
		return;
	}
	bus=device_find_child(bus, "simplebus", 0);
	if(!bus){
		device_printf(dev, "Can't find simplebus\n");
		return;
	}
	bus=device_find_child(bus, "iicoc", 0);
	if(!bus){
		device_printf(dev, "Can't find iicoc\n");
		return;
	}
	bus=device_find_child(bus, "iicbus", 0);
	if(!bus){
		device_printf(dev, "Can't find iicbus\n");
		return;
	}

	struct iic_msg msgs[1] = {{ 0x58 << 1, IIC_M_WR, 2, data}}; 

//	sc = device_get_softc(dev);
	if ((howto & RB_POWEROFF) == RB_POWEROFF){
		//printf("Poweroff requested, shutting down via DA9063!\n");

		data[0]=0x13; data[1]=2;
	        iicbus_transfer(bus, msgs, 1);

		//int error = 
		//data[0]=2;
		//iicbus_write(dev, 0x58, 0x13, data, 1);

		//write = (howto & RB_POWEROFF) != 0;
	} else if ((howto & RB_HALT) == RB_HALT){
		//printf("Halted!\n");

//		data[0]=0x00; data[1]=0; iicbus_transfer(bus, msgs, 1);
//		data[0]=0x0A; data[1]=0x00; iicbus_transfer(bus, msgs, 1);
//		data[0]=0x96; data[1]=0xdf; iicbus_transfer(bus, msgs, 1);
//		data[0]=0x4a; data[1]=0x20; iicbus_transfer(bus, msgs, 1);
//		data[0]=0x4b; data[1]=0x80; iicbus_transfer(bus, msgs, 1);
//		data[0]=0x06; data[1]=0x04; iicbus_transfer(bus, msgs, 1);
//		data[0]=0x0e; data[1]=0x68; iicbus_transfer(bus, msgs, 1);
		
	//	write = (howto & RB_HALT) == 0;

	}else{
		//printf("Reboot requested, resetting via DA9063!\n");
		data[0]=0x00; data[1]=0; iicbus_transfer(bus, msgs, 1);
		data[0]=0x13; data[1]=0x04; iicbus_transfer(bus, msgs, 1);
		data[0]=0x0E; data[1]=0x68; iicbus_transfer(bus, msgs, 1);
	}
	
	//if (write)
	//	SYSCON_MODIFY_4(sc->regmap, sc->offset, sc->mask,
	//	    sc->value & sc->mask);
}

static int
syscon_power_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_is_compatible(dev, "syscon-poweroff")) {
		device_set_desc(dev, "Syscon poweroff");
		return (BUS_PROBE_DEFAULT);
	} else if (ofw_bus_is_compatible(dev, "syscon-reboot")) {
		device_set_desc(dev, "Syscon reboot");
		return (BUS_PROBE_DEFAULT);
	} else if (ofw_bus_is_compatible(dev, "gpio-poweroff")) {
		device_set_desc(dev, "GPIO reboot");
		return (BUS_PROBE_DEFAULT);
	}

	return (ENXIO);
}

static int
syscon_power_attach(device_t dev)
{
	struct syscon_power_softc *sc;
	phandle_t node;
//	int error, 
	int len;
	bool has_mask;

	sc = device_get_softc(dev);
	node = ofw_bus_get_node(dev);

/*
	if (!OF_hasprop(node, "regmap")) {
		device_printf(dev, "could not find regmap\n");
		return (ENXIO);
	}

	error = syscon_get_by_ofw_property(dev, node, "regmap", &sc->regmap);
	if (error != 0) {
		device_printf(dev, "could not get syscon\n");
		return (ENXIO);
	}

	len = OF_getproplen(node, "offset");
	if (len != 4) {
		device_printf(dev, "could not get offset\n");
		return (ENXIO);
	}

	OF_getencprop(node, "offset", &sc->offset, sizeof(sc->offset));
*/
	/* Optional mask */
	has_mask = OF_hasprop(node, "mask");
	if (has_mask) {
		len = OF_getproplen(node, "mask");
		if (len != 4) {
			device_printf(dev, "cannot handle mask\n");
			return (ENXIO);
		}

		OF_getencprop(node, "mask", &sc->mask, sizeof(sc->mask));
	} else {
		sc->mask = 0xffffffff;
	}

	/*
	 * From the device tree specification:
	 *
	 *   Legacy usage: If a node doesn't contain a value property but
	 *   contains a mask property, the mask property is used as the value.
	 */
/*
	if (!OF_hasprop(node, "value")) {
		if (!has_mask) {
			device_printf(dev, "must have a value or a mask\n");
			return (ENXIO);
		}

		sc->value = sc->mask;
	} else {
		len = OF_getproplen(node, "value");
		if (len != 4) {
			device_printf(dev, "cannot handle value\n");
			return (ENXIO);
		}

		OF_getencprop(node, "value", &sc->value, sizeof(sc->value));
	}
*/

	/* Handle reboot after shutdown_panic. */
	//sc->reboot = 0; // ofw_bus_is_compatible(dev, "syscon-reboot");
	sc->shutdown_tag = EVENTHANDLER_REGISTER(shutdown_final,
	    syscon_power_shutdown_final, dev, SHUTDOWN_PRI_DEFAULT); 
	//    sc->reboot ? SHUTDOWN_PRI_LAST + 150 : SHUTDOWN_PRI_LAST);

	return (0);
}

static int
syscon_power_detach(device_t dev)
{
	struct syscon_power_softc *sc;

	sc = device_get_softc(dev);
	EVENTHANDLER_DEREGISTER(shutdown_final, sc->shutdown_tag);

	return (0);
}

static device_method_t syscon_power_methods[] = {
	DEVMETHOD(device_probe,		syscon_power_probe),
	DEVMETHOD(device_attach,	syscon_power_attach),
	DEVMETHOD(device_detach,	syscon_power_detach),

	DEVMETHOD_END
};

DEFINE_CLASS_0(syscon_power, syscon_power_driver, syscon_power_methods,
    sizeof(struct syscon_power_softc));

DRIVER_MODULE(syscon_power, simplebus, syscon_power_driver, NULL, NULL);
