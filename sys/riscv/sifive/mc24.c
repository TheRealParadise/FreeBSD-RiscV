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
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#include "opt_platform.h"

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/module.h>
#include <sys/ctype.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/sysctl.h>

#include <dev/iicbus/iicbus.h>
#include <dev/iicbus/iiconf.h>

#include <dev/ofw/ofw_bus_subr.h>
#include <dev/ofw/ofw_bus.h>

#define BIT(x)					(1UL << (x))

#define MC24_TYPE_SYSCTL			0
#define MC24_SERIAL_SYSCTL			1

#define DEVICE_MC24C02 				0

static int mc24_probe(device_t dev);
static int mc24_attach(device_t dev);
static int mc24_read_1(device_t dev, uint8_t reg, uint8_t *data);
static int mc24_write_1(device_t dev, uint8_t reg, uint8_t data);
static int mc24_detach(device_t dev);
static int mc24_sensor_sysctl(SYSCTL_HANDLER_ARGS);

static device_method_t mc24_methods[] = {
	DEVMETHOD(device_probe,		mc24_probe),
	DEVMETHOD(device_attach,	mc24_attach),
	DEVMETHOD(device_detach,	mc24_detach),
	DEVMETHOD_END
};

#define MAGIC_NUMBER_BYTES			4
#define SERIAL_NUMBER_BYTES			16
#define MAC_ADDR_BYTES				6

struct mc24_softc {
	struct mtx		mtx;
	uint8_t			conf;

	union {
	 const char *cproduct_name;
	 char *product_name;
	};

	char board_serial[SERIAL_NUMBER_BYTES + 1];

};

static driver_t mc24_driver = {
	"mc24_dev",
	mc24_methods,
	sizeof(struct mc24_softc)
};

struct mc24_data {
	const char	*compat;
	const char	*desc;
	uint8_t		flags;
};

struct sifive_product {
	uint16_t id;
	const char *name;
};

static struct sifive_product sifive_products[] = {
	{ 0, "Unknown"},
	{ 2, "HiFive Unmatched" },
};




static struct __attribute__ ((__packed__)) {
	uint8_t  magic[MAGIC_NUMBER_BYTES];
	uint8_t  format_ver;
	uint16_t product_id;
	uint8_t  pcb_revision;
	uint8_t  bom_revision;
	uint8_t  bom_variant;
	uint8_t  serial[SERIAL_NUMBER_BYTES];
	uint8_t  manuf_test_status;
	uint8_t  mac_addr[MAC_ADDR_BYTES];
	uint32_t crc;
} sifive_eeprom;


static struct mc24_data sensor_list[] = {
	{"MC24C02", "Microchip 24c02", DEVICE_MC24C02}
};

static struct ofw_compat_data mc24_compat_data[] = {
	{"microchip,24c02",	(uintptr_t)&sensor_list[0]},
	{NULL,			0}

};

DRIVER_MODULE(MC24DRIVER, iicbus, mc24_driver, 0, 0);
IICBUS_FDT_PNP_INFO(mc24_compat_data);

static int mc24_attach(device_t dev) {
	struct sysctl_oid *sensor_root_oid;
	struct mc24_data *compat_data;
	struct sysctl_ctx_list *ctx;
	struct mc24_softc *sc;
	int error;

//	uint8_t data;

	sc = device_get_softc(dev);
	compat_data = (struct mc24_data *) ofw_bus_search_compatible(dev, mc24_compat_data)->ocd_data;
	sc->conf = compat_data->flags;
	ctx = device_get_sysctl_ctx(dev);

	mtx_init(&sc->mtx, "Microchip eeprom (24c02)", "eeprom", MTX_DEF);

	error = iicdev_readfrom(dev, 0, (void *)&sifive_eeprom, sizeof(sifive_eeprom), IIC_DONTWAIT);
	if (error != 0) device_printf(dev, "Failed to read from device\n");

	sc->product_name="Unknown";
	bzero(sc->board_serial, sizeof(sc->board_serial));


	snprintf(sc->board_serial, sizeof(sc->board_serial), "%s", sifive_eeprom.serial);

	for (int i = 0; i < 2; i++){ // ARRAY_SIZE(sifive_products); i++) {
		if (sifive_products[i].id == sifive_eeprom.product_id) {
			sc->cproduct_name = sifive_products[i].name;
			break;
		}
	}
	

	printf("SiFive PCB EEPROM format v%u\n", sifive_eeprom.format_ver);
	printf("Product ID: %04hx (%s)\n", sifive_eeprom.product_id, sc->product_name);
	printf("PCB/BOM revision: %x/%c/%x\n", sifive_eeprom.pcb_revision, sifive_eeprom.bom_revision, sifive_eeprom.bom_variant);
	printf("Serial number: %s\n", sc->board_serial);
	printf("Ethernet MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
	       sifive_eeprom.mac_addr[0], sifive_eeprom.mac_addr[1], sifive_eeprom.mac_addr[2],
	       sifive_eeprom.mac_addr[3], sifive_eeprom.mac_addr[4], sifive_eeprom.mac_addr[5]);

	printf("Board Manufacturing Test: ");
	switch(sifive_eeprom.manuf_test_status){
		case 1: printf("Passed\n"); break;
		case 2: printf("Failed\n"); break;
		default: printf("Unknown\n"); break;
	}


	sensor_root_oid = SYSCTL_ADD_NODE(ctx, SYSCTL_STATIC_CHILDREN(_hw), OID_AUTO, "board", CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, "Thermal Sensor Information");
	if (sensor_root_oid == NULL) return (ENXIO);


	/* get serial number register */
//	if (mc24_read_1(dev, mc24_STATUS_REG, &data) != 0) return (ENXIO);
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(sensor_root_oid), OID_AUTO, "serial", CTLTYPE_STRING | CTLFLAG_RD, dev, MC24_SERIAL_SYSCTL, mc24_sensor_sysctl, "IK1", compat_data->desc);

//	if (mc24_read_1(dev, mc24_STATUS_REG, &data) != 0) return (ENXIO);
	SYSCTL_ADD_PROC(ctx, SYSCTL_CHILDREN(sensor_root_oid), OID_AUTO, "type", CTLTYPE_STRING | CTLFLAG_RD, dev, MC24_TYPE_SYSCTL, mc24_sensor_sysctl, "IK1", compat_data->desc);


	return (0);
}

static int
mc24_probe(device_t dev)
{
	struct mc24_data *compat_data;

	if (!ofw_bus_status_okay(dev)) return (ENXIO);

	compat_data = (struct mc24_data *) ofw_bus_search_compatible(dev, mc24_compat_data)->ocd_data;
	if (!compat_data) return (ENXIO);
	device_set_desc(dev, compat_data->compat);

	return (BUS_PROBE_GENERIC);
}

static int
mc24_detach(device_t dev)
{
	struct mc24_softc *sc;

	sc = device_get_softc(dev);
	mtx_destroy(&sc->mtx);

	return (0);
}

static int mc24_read_1(device_t dev, uint8_t reg, uint8_t *data){
	int error;

	error = iicdev_readfrom(dev, reg, (void *) data, 1, IIC_DONTWAIT);
	if (error != 0) device_printf(dev, "Failed to read from device\n");

	return (error);
}

static int mc24_write_1(device_t dev, uint8_t reg, uint8_t data) {
	int error;

	error = iicdev_writeto(dev, reg, (void *) &data, 1, IIC_DONTWAIT);
	if (error != 0) device_printf(dev, "Failed to write to device\n");

	return (error);
}

/*
static int mc24_read_temperature(device_t dev, int32_t *temperature, bool remote_measure){
	uint8_t data, offset, reg;
	struct mc24_softc *sc;
	int error;

	sc = device_get_softc(dev);

	mtx_lock(&sc->mtx);

	error = mc24_read_1(dev, mc24_CONVERSION_RATE_REG, &data);
	if (error != 0)
		goto fail;

	// trigger sample
	error = mc24_write_1(dev, mc24_ONESHOT_REG, 0xFF);
	if (error != 0)
		goto fail;

	// wait for conversion time 
	DELAY(mc24_SENSOR_MAX_CONV_TIME/(1UL<<data));

	// read config register offset
	error = mc24_read_1(dev, mc24_CONFIG_REG_R, &data);
	if (error != 0)
		goto fail;

	offset = (data & mc24_CONFIG_REG_TEMP_RANGE_BIT ?
	    mc24_EXTENDED_TEMP_MODIFIER : 0);

	reg = remote_measure ?
	    mc24_GLOBAL_TEMP_REG_MSB : mc24_LOCAL_TEMP_REG_MSB;

	// read temeperature value
	error = mc24_read_1(dev, reg, &data);
	if (error != 0)
		goto fail;

	data -= offset;
	*temperature = signed_extend32(data, 0, 8) << 4;

	if (remote_measure) {
		if (sc->conf & mc24_REMOTE_TEMP_DOUBLE_REG) {
			error = mc24_read_1(dev,
			    mc24_GLOBAL_TEMP_REG_LSB, &data);
			if (error != 0)
				goto fail;

			*temperature |= data >> 4;
		}
	} else {
		if (sc->conf & mc24_LOCAL_TEMP_DOUBLE_REG) {
			error = mc24_read_1(dev,
			    mc24_LOCAL_TEMP_REG_LSB, &data);
			if (error != 0)
				goto fail;

			*temperature |= data >> 4;
		}
	}
	*temperature = (((*temperature + mc24_C_TO_K_FIX) * 10) >> 4);

fail:
	mtx_unlock(&sc->mtx);
	return (error);
}
*/

static int mc24_sensor_sysctl(SYSCTL_HANDLER_ARGS) {
	device_t dev=arg1;
	
	struct mc24_softc *sc;
	sc = device_get_softc(dev);

	switch(arg2){
		case MC24_TYPE_SYSCTL: return (sysctl_handle_string(oidp, (char *)sc->product_name, strlen(sc->product_name), req));
		case MC24_SERIAL_SYSCTL: return (sysctl_handle_string(oidp, sc->board_serial, strlen(sc->board_serial), req));
		default: return (sysctl_handle_string(oidp, "Invalid", 7, req));
	}
}
