#ifndef __PMO_QUIRKS_H__
#define __PMO_QUIRKS_H__

#define _SIMPLESSD_SHOULD_FIXUP(irq) true

#define _SIMPLESSD_FIXUP(msg) { \
	msg->arch_addr_lo.redirect_hint = true; \
	msg->arch_data.delivery_mode = APIC_DELIVERY_MODE_LOWESTPRIO;}

#endif
